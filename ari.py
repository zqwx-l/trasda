#!/usr/bin/env python3
"""Aria Game Interactive Headless Client
Usage: python ari.py [loginId] [password]

Commands:
  login    - HTTP login + TCP connect + send login packet
  ping     - Send ping (cmd 900)
  status   - Show connection status
  raw <hex> - Send raw hex payload (auto prepends BE header)
  cmd <id> - Send empty command with given ID
  recv     - Wait for next response (5s timeout)
  dump     - Decode last response as FlatBuffer
  quit     - Exit
"""
import struct, socket, time, sys, threading, base64

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# === CONFIG ===
LOGIN_URL = "https://login-en-dev.mcorz.com/login/"
GAME_HOST = "47.236.159.0"
GAME_PORT = 8000

# 430-byte login capture (correct BE header: frame_len=426, cmd=100)
LOGIN_CAPTURE = base64.b64decode(
    "AAABqgBkOAAAAAAAAAAwAGQABAAIAAwAEABQABQAGAAcACAAJAAoACwAMAAAADQAOAA8AFgAQABE"
    "AEgATAAwAAAAsAIAAAEAAABUAQAAKAEAABgBAAABAAAA+AAAAMwAAACwAAAAoAAAAAAFAADQAgAA"
    "eAAAAGQPAABIAAAAPAAAADAAAAAkAAAAGAAAADHREg2fAQAAV/+YAAAAAAAAAAAAAAAAAAAAAAAA"
    "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAgAAAAMjViMzU5NzUyZWY1ODZiMDJjZWNkMjMzNTQyMzI3"
    "NDQAAAAAFgAAAEFSTXY3IFZGUHYzIE5FT04gVk1ILTMAAAQAAABXSUZJAAAAABAAAABTYW1zdW5n"
    "IFNNLUEyMTdNAAAAACIAAABBbmRyb2lkIE9TIDEyIC8gQVBJLTMyIChWNDE3SVIvODEpAAATAAAA"
    "MjAyNS0wNS0wNi0xMC01OS00NwAHAAAARkJfMTAyMAAgAAAAQTE0ODc5NDkzNEM2NEM5RTlBQjg1"
    "RDE0RDNFNTM2RUUAAAAACAAAADgwMzQxOTAgAAAAAA=="
)

# Command names
CMD_NAMES = {
    100: "Login", 900: "Ping", 901: "Pong", 999: "LoginQueue",
    2: "GetConv", 385: "Queue", 5601: "Data5601", 5602: "Data5602",
    111: "EnterStage", 192: "Action", 80: "Chat", 87: "Emote",
    160: "Move", 162: "MoveSync", 106: "Skill", 175: "Buff",
    220: "Equip", 210: "Inventory", 211: "ItemUse",
    290: "Quest", 470: "Gacha", 480: "Shop",
    881: "Mail", 886: "Event", 300: "Friend",
    765: "Heartbeat", 280: "StageResult",
}


class AriaClient:
    def __init__(self):
        self.sock = None
        self.token = None
        self.role_id = None
        self.http_info = {}
        self.login_id = None
        self.password = None
        self.connected = False
        self.logged_in = False
        self.responses = []
        self.receiver_running = False
        self.last_response = None

    def http_login(self, login_id, password):
        """Step 1: HTTP login to get token"""
        self.login_id = login_id
        self.password = password
        print(f"[*] HTTP login: {login_id}...")
        resp = requests.post(LOGIN_URL, verify=False, data={
            "publisher": 688, "serverId": 1,
            "loginId": login_id, "password": password
        }, timeout=10)
        info = resp.json()
        self.token = info.get("token", "")
        self.role_id = int(info.get("roleId", 0))
        self.http_info = info
        print(f"[+] Token: {self.token}")
        print(f"[+] RoleId: {self.role_id}")
        return info

    def connect(self):
        """Step 2: TCP connect"""
        print(f"[*] Connecting to {GAME_HOST}:{GAME_PORT}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(10)
        self.sock.connect((GAME_HOST, GAME_PORT))
        self.connected = True
        print(f"[+] Connected!")

    def recv_frame(self, timeout=5):
        """Receive one framed response (4-byte BE len + payload)"""
        old = self.sock.gettimeout()
        self.sock.settimeout(timeout)
        try:
            hdr = self._recvn(4)
            if not hdr:
                return None, None
            fl = struct.unpack('>I', hdr)[0]
            body = self._recvn(fl)
            if not body:
                return None, None
            cmd = struct.unpack('>H', body[:2])[0] if len(body) >= 2 else -1
            flags = struct.unpack('>H', body[2:4])[0] if len(body) >= 4 else 0
            payload = body[4:] if len(body) > 4 else b""
            return cmd, body
        except socket.timeout:
            return None, None
        finally:
            self.sock.settimeout(old)

    def _recvn(self, n):
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_frame(self, cmd, payload=b"", flags=0x1000):
        """Send framed command (4-byte BE len + 2-byte BE cmd + 2-byte BE flags + payload)"""
        body = struct.pack('>H', cmd) + struct.pack('>H', flags) + payload
        frame = struct.pack('>I', len(body)) + body
        self.sock.sendall(frame)
        return True

    def send_raw(self, data):
        """Send raw bytes"""
        self.sock.sendall(data)

    def do_login(self):
        """Full login flow: read init -> send login packet -> read responses"""
        if not self.token:
            print("[!] No token. Run 'login' first.")
            return

        # Build login packet from capture
        pkt = bytearray(LOGIN_CAPTURE)

        FB = 6
        root = struct.unpack_from('<I', pkt, FB)[0]
        tpos = FB + root
        soff = struct.unpack_from('<i', pkt, tpos)[0]
        vpos = tpos - soff

        def field_abs(idx):
            o = struct.unpack_from('<H', pkt, vpos + 4 + idx * 2)[0]
            return tpos + o if o else None

        def patch_string(idx, new_val):
            """Patch a FlatBuffer string field (pad/truncate to original length)"""
            a = field_abs(idx)
            if not a: return None
            r = struct.unpack_from('<i', pkt, a)[0]
            s = a + r
            n = struct.unpack_from('<I', pkt, s)[0]
            old = pkt[s+4:s+4+n].decode()
            padded = new_val[:n].ljust(n, '\x00')
            pkt[s+4:s+4+n] = padded.encode()
            return old

        def patch_long(idx, new_val):
            """Patch a FlatBuffer long (int64) field"""
            a = field_abs(idx)
            if not a: return None
            old = struct.unpack_from('<q', pkt, a)[0]
            struct.pack_into('<q', pkt, a, new_val)
            return old

        # Patch Loginid (field 2) - MUST match token's account
        old_id = patch_string(2, self.login_id)
        print(f"  Loginid: '{old_id}' -> '{self.login_id}'")

        # Patch Token (field 3)
        old_t = patch_string(3, self.token)
        print(f"  Token: {old_t[:16]}... -> {self.token[:16]}...")

        # Patch Time (field 4) - use server time
        http_time = int(self.http_info.get('time', time.time() * 1000))
        old_time = patch_long(4, http_time)
        print(f"  Time: {old_time} -> {http_time}")

        # Patch RoleId (field 17)
        old_role = patch_long(17, self.role_id)
        print(f"  RoleId: {old_role} -> {self.role_id}")

        # Read init
        print("[*] Reading server init...")
        for _ in range(5):
            cmd, body = self.recv_frame(timeout=2)
            if cmd is not None:
                name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
                print(f"  <- {name} (cmd={cmd}) len={len(body)}")
                self.responses.append(("init", cmd, body))
            else:
                break

        # Send login
        print(f"[*] Sending login ({len(pkt)}B) header={pkt[:6].hex()}...")
        self.send_raw(bytes(pkt))

        # Read responses
        print("[*] Waiting for login response...")
        start = time.time()
        while time.time() - start < 15:
            cmd, body = self.recv_frame(timeout=3)
            if cmd is not None:
                name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
                elapsed = int(time.time() - start)
                payload_hex = body[4:].hex() if len(body) > 4 else ""
                e1009 = " ← E1009!" if "f103" in payload_hex else ""
                print(f"  [{elapsed}s] <- {name} (cmd={cmd}) len={len(body)}{e1009}")
                self.responses.append(("login_resp", cmd, body))
                self.last_response = body
                self._auto_decode(cmd, body)
                if cmd == 100:
                    self.logged_in = True
                    print(f"[+] Login confirmed (cmd=100 response)")
                elif "f103" in payload_hex:
                    print(f"[!] E1009 detected - login rejected")
            else:
                break

        if self.logged_in:
            print("[+] Login successful! Session active.")
        else:
            print("[!] Login may have failed. Check responses above.")

    def do_ping(self):
        """Send ping"""
        if not self.connected:
            print("[!] Not connected")
            return
        self.send_frame(900)
        print("[>] Ping sent (cmd=900)")
        cmd, body = self.recv_frame(timeout=3)
        if cmd is not None:
            name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
            print(f"  <- {name} (cmd={cmd}) len={len(body)}")
            return cmd
        else:
            print("  No response (timeout)")
            return None

    def do_recv(self, timeout=5):
        """Wait for next response"""
        if not self.connected:
            print("[!] Not connected")
            return
        cmd, body = self.recv_frame(timeout=timeout)
        if cmd is not None:
            name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
            print(f"  <- {name} (cmd={cmd}) len={len(body)} hex={body[:60].hex()}")
            self.last_response = body
            self._auto_decode(cmd, body)
            return cmd, body
        else:
            print("  No response (timeout)")
            return None, None

    def _auto_decode(self, cmd, body):
        """Auto-decode known command responses"""
        if cmd == 104:
            self._decode_role_info(body)

    def _decode_role_info(self, body):
        """Decode cmd=104 GetRoleInfo response — hexdump + attempt FlatBuffer decode"""
        fb = body[4:]  # skip cmd(2)+flags(2)
        print(f"\n  === CMD=104 RAW ({len(fb)}B) ===")
        for i in range(0, min(len(fb), 512), 16):
            chunk = fb[i:i+16]
            hx = ' '.join(f'{b:02x}' for b in chunk)
            asc = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            print(f"    {i:04x}: {hx:<48s} {asc}")
        if len(fb) > 512:
            print(f"    ... ({len(fb)-512} more bytes)")
        print("  =================================\n")

        # Also try raw FlatBuffer with different skip amounts
        for skip in [0, 2, 4, 6]:
            data = body[skip:]
            if len(data) < 8:
                continue
            try:
                root = struct.unpack_from('<I', data, 0)[0]
                if root > len(data) or root < 4:
                    continue
                tpos = root
                soff = struct.unpack_from('<i', data, tpos)[0]
                if abs(soff) > len(data):
                    continue
                vpos = tpos - soff
                if vpos + 4 > len(data):
                    continue
                vsize = struct.unpack_from('<H', data, vpos)[0]
                if vsize < 4 or vsize > 200:
                    continue
                num_fields = (vsize - 4) // 2
                print(f"  [skip={skip}] FlatBuffer: root={root} vpos={vpos} vsize={vsize} num_fields={num_fields}")
                # Try to read string fields
                for fi in range(num_fields):
                    voff = struct.unpack_from('<H', data, vpos + 4 + fi * 2)[0]
                    if voff == 0:
                        continue
                    abs_off = tpos + voff
                    if abs_off + 4 > len(data):
                        continue
                    # Try as string (uoffset)
                    try:
                        str_rel = struct.unpack_from('<i', data, abs_off)[0]
                        if str_rel > 0 and abs_off + str_rel + 4 <= len(data):
                            str_abs = abs_off + str_rel
                            slen = struct.unpack_from('<I', data, str_abs)[0]
                            if 0 < slen < 200 and str_abs + 4 + slen <= len(data):
                                s = data[str_abs+4:str_abs+4+slen].decode('utf-8', errors='replace')
                                if s.strip() and s.isprintable():
                                    print(f"    field[{fi}] str: {s}")
                    except:
                        pass
                    # Try as int32
                    try:
                        ival = struct.unpack_from('<i', data, abs_off)[0]
                        if 1 <= ival < 1000000:
                            pass  # skip small ints for now
                    except:
                        pass
            except:
                continue

    def do_send_cmd(self, cmd_id):
        """Send empty command"""
        if not self.connected:
            print("[!] Not connected")
            return
        self.send_frame(cmd_id)
        print(f"[>] Sent cmd={cmd_id}")

    def do_send_raw(self, hex_str):
        """Send raw hex payload as a framed command"""
        if not self.connected:
            print("[!] Not connected")
            return
        try:
            payload = bytes.fromhex(hex_str.replace(" ", ""))
            frame = struct.pack('>I', len(payload)) + payload
            self.send_raw(frame)
            print(f"[>] Sent {len(payload)}B raw: {payload[:40].hex()}")
        except ValueError:
            print("[!] Invalid hex")

    def status(self):
        """Show status"""
        print(f"  Connected: {self.connected}")
        print(f"  Logged in: {self.logged_in}")
        print(f"  Token: {self.token[:20]}..." if self.token else "  Token: None")
        print(f"  RoleId: {self.role_id}")
        print(f"  LoginId: {self.login_id}")
        print(f"  Responses: {len(self.responses)}")
        if self.last_response:
            cmd = struct.unpack('>H', self.last_response[:2])[0] if len(self.last_response) >= 2 else -1
            print(f"  Last response: cmd={cmd} len={len(self.last_response)}")

    def disconnect(self):
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False
        self.logged_in = False
        print("[*] Disconnected")


def main():
    import os
    os.environ['PYTHONWARNINGS'] = 'ignore:Unverified'

    client = AriaClient()

    # Defaults
    default_id = "8034174"
    default_pw = "gf6dhbnx"

    if len(sys.argv) >= 3:
        default_id = sys.argv[1]
        default_pw = sys.argv[2]
    elif len(sys.argv) == 2:
        default_id = sys.argv[1]

    print("=" * 50)
    print("  Aria Game Interactive Headless Client")
    print("=" * 50)
    print(f"  Default: {default_id}")
    print()
    print("Commands: login, ping, status, cmd <id>,")
    print("          raw <hex>, recv, quit")
    print()

    while True:
        try:
            line = input("aria> ").strip()
            if not line:
                continue

            parts = line.split()
            cmd = parts[0].lower()

            if cmd == "quit" or cmd == "exit":
                client.disconnect()
                break

            elif cmd == "login":
                lid = parts[1] if len(parts) > 1 else default_id
                pw = parts[2] if len(parts) > 2 else default_pw
                try:
                    client.http_login(lid, pw)
                    client.connect()
                    client.do_login()
                except Exception as e:
                    print(f"[!] Error: {e}")

            elif cmd == "ping":
                result = client.do_ping()
                if result is None:
                    print("[!] Connection might be dead")

            elif cmd == "status":
                client.status()

            elif cmd == "cmd":
                if len(parts) < 2:
                    print("Usage: cmd <command_id>")
                else:
                    client.do_send_cmd(int(parts[1]))
                    # Auto-read response
                    rcmd, rbody = client.do_recv(timeout=3)

            elif cmd == "raw":
                if len(parts) < 2:
                    print("Usage: raw <hex_string>")
                else:
                    client.do_send_raw(parts[1])
                    rcmd, rbody = client.do_recv(timeout=3)

            elif cmd == "recv":
                timeout = int(parts[1]) if len(parts) > 1 else 5
                client.do_recv(timeout=timeout)

            elif cmd == "reconnect":
                client.disconnect()
                try:
                    client.connect()
                    client.do_login()
                except Exception as e:
                    print(f"[!] Error: {e}")

            elif cmd == "disconnect":
                client.disconnect()

            elif cmd == "keepalive":
                # Auto-ping loop
                interval = int(parts[1]) if len(parts) > 1 else 10
                print(f"[*] Keepalive every {interval}s (Ctrl+C to stop)")
                try:
                    while True:
                        time.sleep(interval)
                        result = client.do_ping()
                        if result is None:
                            print("[!] Connection dead!")
                            break
                except KeyboardInterrupt:
                    print("\n[*] Keepalive stopped")

            else:
                print(f"Unknown command: {cmd}")
                print("Commands: login, ping, status, cmd <id>,")
                print("          raw <hex>, recv, reconnect,")
                print("          keepalive [sec], disconnect, quit")

        except KeyboardInterrupt:
            print()
            continue
        except EOFError:
            break
        except Exception as e:
            print(f"[!] Error: {e}")

if __name__ == "__main__":
    main()

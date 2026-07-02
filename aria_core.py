"""
Aria Game Headless Client — CORE
=================================
Protocol layer: HTTP login, TCP connect, send/recv frames, keepalive.

DO NOT MODIFY THIS FILE unless protocol changes.
Game logic goes in aria_game.py.
"""
import struct, socket, time, sys, base64

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
    "NDQAAAAAFgAAAEFSTXY3IFZGUHYzIE5FT04gVk1JTUAAAAAIAAAAODAzNDE5MCAAAAAAAA=="
)

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


class AriaCore:
    """Core protocol layer — login, connect, send/recv, keepalive."""

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
        self.last_response = None

    # ── HTTP Login ──────────────────────────────────────────────

    def http_login(self, login_id, password):
        """HTTP login to get token + roleId."""
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

    # ── TCP Connection ──────────────────────────────────────────

    def connect(self):
        """TCP connect to game server."""
        print(f"[*] Connecting to {GAME_HOST}:{GAME_PORT}...")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.sock.settimeout(10)
        self.sock.connect((GAME_HOST, GAME_PORT))
        self.connected = True
        print(f"[+] Connected!")

    def disconnect(self):
        """Close TCP connection."""
        if self.sock:
            try:
                self.sock.close()
            except:
                pass
            self.sock = None
        self.connected = False
        self.logged_in = False
        print("[*] Disconnected")

    def reconnect(self):
        """Disconnect + connect + login."""
        self.disconnect()
        self.connect()
        self.do_login()

    # ── Frame I/O ───────────────────────────────────────────────

    def recv_frame(self, timeout=5):
        """Receive one framed response: 4-byte BE len + payload.
        Returns (cmd, body) or (None, None) on timeout/disconnect.
        body = full payload including cmd(2) + flags(2) + data.
        """
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
            return cmd, body
        except socket.timeout:
            return None, None
        finally:
            self.sock.settimeout(old)

    def _recvn(self, n):
        """Receive exactly n bytes."""
        buf = b""
        while len(buf) < n:
            chunk = self.sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    def send_frame(self, cmd, payload=b"", flags=0x1000):
        """Send framed command: 4-byte BE len + 2-byte BE cmd + 2-byte BE flags + payload."""
        body = struct.pack('>H', cmd) + struct.pack('>H', flags) + payload
        frame = struct.pack('>I', len(body)) + body
        self.sock.sendall(frame)
        return True

    def send_raw(self, data):
        """Send raw bytes (no framing)."""
        self.sock.sendall(data)

    # ── Login Flow ──────────────────────────────────────────────

    def do_login(self):
        """Full login flow: patch capture → read init → send → read responses."""
        if not self.token:
            print("[!] No token. Run http_login() first.")
            return False

        pkt = bytearray(LOGIN_CAPTURE)

        # FlatBuffer navigation
        FB = 6
        root = struct.unpack_from('<I', pkt, FB)[0]
        tpos = FB + root
        soff = struct.unpack_from('<i', pkt, tpos)[0]
        vpos = tpos - soff

        def field_abs(idx):
            o = struct.unpack_from('<H', pkt, vpos + 4 + idx * 2)[0]
            return tpos + o if o else None

        def patch_string(idx, new_val):
            a = field_abs(idx)
            if not a:
                return None
            r = struct.unpack_from('<i', pkt, a)[0]
            s = a + r
            n = struct.unpack_from('<I', pkt, s)[0]
            old = pkt[s+4:s+4+n].decode()
            padded = new_val[:n].ljust(n, '\x00')
            pkt[s+4:s+4+n] = padded.encode()
            return old

        def patch_long(idx, new_val):
            a = field_abs(idx)
            if not a:
                return None
            old = struct.unpack_from('<q', pkt, a)[0]
            struct.pack_into('<q', pkt, a, new_val)
            return old

        # Patch fields
        old_id = patch_string(2, self.login_id)
        print(f"  Loginid: '{old_id}' -> '{self.login_id}'")

        old_t = patch_string(3, self.token)
        print(f"  Token: {old_t[:16]}... -> {self.token[:16]}...")

        http_time = int(self.http_info.get('time', time.time() * 1000))
        old_time = patch_long(4, http_time)
        print(f"  Time: {old_time} -> {http_time}")

        old_role = patch_long(17, self.role_id)
        print(f"  RoleId: {old_role} -> {self.role_id}")

        # Read server init
        print("[*] Reading server init...")
        for _ in range(5):
            cmd, body = self.recv_frame(timeout=2)
            if cmd is not None:
                name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
                print(f"  <- {name} (cmd={cmd}) len={len(body)}")
                self.responses.append(("init", cmd, body))
            else:
                break

        # Send login packet
        print(f"[*] Sending login ({len(pkt)}B) header={pkt[:6].hex()}...")
        self.send_raw(bytes(pkt))

        # Read login responses
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
                self.on_response(cmd, body)  # hook for game layer
                if cmd == 100:
                    self.logged_in = True
                    print("[+] Login confirmed (cmd=100 response)")
                elif "f103" in payload_hex:
                    print("[!] E1009 detected - login rejected")
            else:
                break

        if self.logged_in:
            print("[+] Login successful! Session active.")
        else:
            print("[!] Login may have failed. Check responses above.")
        return self.logged_in

    # ── Convenience ─────────────────────────────────────────────

    def do_ping(self):
        """Send ping and wait for pong."""
        if not self.connected:
            print("[!] Not connected")
            return None
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
        """Wait for next response and decode."""
        if not self.connected:
            print("[!] Not connected")
            return None, None
        cmd, body = self.recv_frame(timeout=timeout)
        if cmd is not None:
            name = CMD_NAMES.get(cmd, f"CMD_{cmd}")
            print(f"  <- {name} (cmd={cmd}) len={len(body)} hex={body[:60].hex()}")
            self.last_response = body
            self.on_response(cmd, body)  # hook for game layer
            return cmd, body
        else:
            print("  No response (timeout)")
            return None, None

    def do_send_cmd(self, cmd_id):
        """Send empty command by ID."""
        if not self.connected:
            print("[!] Not connected")
            return
        self.send_frame(cmd_id)
        print(f"[>] Sent cmd={cmd_id}")

    def do_send_raw(self, hex_str):
        """Send raw hex payload as a framed command."""
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
        """Print connection status."""
        print(f"  Connected: {self.connected}")
        print(f"  Logged in: {self.logged_in}")
        print(f"  Token: {self.token[:20]}..." if self.token else "  Token: None")
        print(f"  RoleId: {self.role_id}")
        print(f"  LoginId: {self.login_id}")
        print(f"  Responses: {len(self.responses)}")
        if self.last_response:
            cmd = struct.unpack('>H', self.last_response[:2])[0] if len(self.last_response) >= 2 else -1
            print(f"  Last response: cmd={cmd} len={len(self.last_response)}")

    # ── Hook for game layer ─────────────────────────────────────

    def on_response(self, cmd, body):
        """Override in subclass to handle responses (decode, etc.)."""
        pass

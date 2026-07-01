#!/usr/bin/env python3
"""
Aria Headless Client — Interactive Termux Version
==================================================
pip install requests
python3 aria_headless.py
"""
import requests, socket, struct, time, warnings, urllib3, sys, threading

warnings.filterwarnings('ignore')
urllib3.disable_warnings()

LOGIN_URL = "https://login-en-dev.mcorz.com/login/"
HEADERS = {
    "X-Unity-Version": "2018.4.36f1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; Infinix X6858)",
}

CMD_NAMES = {
    100: "Login", 111: "GetItems", 900: "Ping", 901: "GetConv",
    902: "DataEnd", 999: "Error", 5601: "Queue", 5602: "Timeout",
}

# Full 466-byte login packet captured from game via Frida
LOGIN_TEMPLATE = bytes.fromhex(
    "5fc5020051000001d632b5190000000000000000ba0100000064380000000000"
    "000030006000040008000c0010005000140018001c002000240028002c003000"
    "0000340038003c0058004000440048004c0030000000b0020000010000006801"
    "00003c0100002c010000010000000c010000cc000000ac0000009c0000005706"
    "0000d002000074000000061e000044000000380000002c000000200000001400"
    "00006134b5199f01000047ff9800000000000000000000000000000000000000"
    "0000000000000000000000000000000000002000000030386364613963353365"
    "3836363637633435626161343064393662303936333500000000140000004152"
    "4d3634204650204153494d44204145532d380000000004000000574946490000"
    "000015000000494e46494e495820496e66696e69782058363835380000003500"
    "0000416e64726f6964204f53203136202f204150492d33362028425032412e32"
    "35303630352e3033312e41332f32303133353030323529000000130000003230"
    "32352d30352d30362d31302d35392d3437000700000046425f31303230002000"
    "0000324533413736464445454334373241334430334136303835464537464632"
    "423400000000070000003830333431373400"
)


def extract_strings(data):
    out, cur = [], b""
    for b in data:
        if 32 <= b < 127:
            cur += bytes([b])
        else:
            if len(cur) >= 4:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = b""
    if len(cur) >= 4:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def parse_responses(data):
    results, off = [], 0
    while off + 6 <= len(data):
        length = struct.unpack(">I", data[off:off+4])[0]
        total = 4 + length
        if off + total > len(data):
            break
        opcode = struct.unpack(">H", data[off+4:off+6])[0]
        body = data[off+6:off+total]
        results.append((length, opcode, body))
        off += total
    return results


def build_login_packet(token, account):
    pkt = bytearray(LOGIN_TEMPLATE)
    ts = int(time.time() * 1000) & 0xFFFFFFFF
    pkt[8:12] = struct.pack("<I", ts)
    tok = token.upper().encode("ascii")[:32]
    pkt[418:418+len(tok)] = tok
    acct = account.encode("ascii")
    pkt[458:458+len(acct)] = acct
    return bytes(pkt)


def http_login(account, password):
    data = f"publisher=688&serverId=1&loginId={account}&password={password}"
    r = requests.post(LOGIN_URL, data=data, headers=HEADERS, timeout=10, verify=False)
    return r.json()


class Client:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = None
        self.alive = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        self.alive = True

    def send_raw(self, opcode, body=b""):
        payload = struct.pack(">H", opcode) + body
        pkt = struct.pack(">I", len(payload)) + payload
        self.sock.sendall(pkt)
        name = CMD_NAMES.get(opcode, f"0x{opcode:04X}")
        print(f"  → {name} sent ({len(pkt)}B)")

    def recv_forever(self):
        while self.alive:
            try:
                data = self.sock.recv(65536)
                if not data:
                    print("\n  ✗ Disconnected")
                    self.alive = False
                    break
                for length, opcode, body in parse_responses(data):
                    name = CMD_NAMES.get(opcode, f"0x{opcode:04X}")
                    ts = time.strftime("%H:%M:%S")
                    if opcode == 999 and len(body) >= 2:
                        err = struct.unpack(">H", body[0:2])[0]
                        strs = extract_strings(body[2:])
                        print(f"\n  [{ts}] ← {name} err={err}", end="")
                        if strs:
                            print(f" \"{strs[0]}\"", end="")
                        print(f" ({len(body)}B)")
                    elif opcode == 900:
                        print(f"\n  [{ts}] ← Pong ({len(body)}B)")
                    else:
                        strs = extract_strings(body)
                        extra = f' "{strs[0]}"' if strs else ""
                        print(f"\n  [{ts}] ← {name} (0x{opcode:04X}){extra} ({len(body)}B)")
                    sys.stdout.write("\n> ")
                    sys.stdout.flush()
            except socket.timeout:
                continue
            except Exception as e:
                if self.alive:
                    print(f"\n  ✗ Error: {e}")
                self.alive = False
                break

    def close(self):
        self.alive = False
        if self.sock:
            try: self.sock.close()
            except: pass


def main():
    print("=" * 48)
    print("   Aria Headless Client — Termux")
    print("=" * 48)
    print("  Commands after login:")
    print("    ping        — keepalive")
    print("    send <N>    — send opcode N")
    print("    items       — GetItems (111)")
    print("    data        — DataEnd (902)")
    print("    status      — connection info")
    print("    quit        — exit")
    print("=" * 48)

    client = None
    account = token = gs = ""

    while True:
        try:
            cmd = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            if client: client.close()
            print("\nBye!")
            break

        if not cmd:
            continue

        if cmd in ("quit", "exit", "q"):
            if client: client.close()
            print("Bye!")
            break

        if cmd == "login":
            account = input("  Username: ").strip()
            password = input("  Password: ").strip()
            if not account or not password:
                print("  ✗ Required")
                continue

            print(f"  [1] HTTP login...")
            try:
                r = http_login(account, password)
            except Exception as e:
                print(f"  ✗ {e}")
                continue

            if r.get("status") != 0:
                print(f"  ✗ Failed: {r}")
                continue

            token = r.get("token", "")
            gs = r.get("gameServer", "")
            oid = r.get("openId", "")
            rid = r.get("roleId", "")
            print(f"  ✓ Token  : {token[:16]}...")
            print(f"  ✓ Server : {gs}")
            print(f"  ✓ OpenID : {oid} | RoleID : {rid}")

            if ":" not in gs:
                print(f"  ✗ Bad server: {gs}")
                continue

            host, port = gs.split(":")
            print(f"  [2] TCP connect...")
            try:
                if client: client.close()
                client = Client(host, int(port))
                client.connect()
                t = threading.Thread(target=client.recv_forever, daemon=True)
                t.start()
            except Exception as e:
                print(f"  ✗ {e}")
                continue

            print(f"  [3] Send login packet...")
            pkt = build_login_packet(token, account)
            try:
                client.sock.sendall(pkt)
                print(f"  ✓ Login sent ({len(pkt)}B)")
            except Exception as e:
                print(f"  ✗ {e}")
                continue

            print(f"  [4] Waiting responses...")
            time.sleep(3)
            print(f"  [5] Ping...")
            client.send_raw(900)
            time.sleep(1)
            print(f"\n  ✓ Ready! Type commands.")

        elif cmd == "ping":
            if not client or not client.alive:
                print("  ✗ Not connected")
                continue
            client.send_raw(900)

        elif cmd == "items":
            if not client or not client.alive:
                print("  ✗ Not connected")
                continue
            client.send_raw(111)

        elif cmd == "data":
            if not client or not client.alive:
                print("  ✗ Not connected")
                continue
            client.send_raw(902)

        elif cmd.startswith("send "):
            if not client or not client.alive:
                print("  ✗ Not connected")
                continue
            try:
                op = int(cmd.split()[1])
                client.send_raw(op)
            except:
                print("  ✗ Usage: send <opcode>")

        elif cmd == "status":
            if client and client.alive:
                print(f"  ✓ {client.host}:{client.port} | {account}")
            else:
                print("  ✗ Disconnected")

        else:
            try:
                op = int(cmd)
                if client and client.alive:
                    client.send_raw(op)
                else:
                    print("  ✗ Not connected")
            except ValueError:
                print(f"  ✗ Unknown: {cmd}")


if __name__ == "__main__":
    main()

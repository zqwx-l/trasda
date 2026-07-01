#!/usr/bin/env python3
"""Aria Debug Client v4.1 — FlatBuffer-aware error parsing"""
import requests, socket, struct, time, warnings, urllib3, sys, threading

warnings.filterwarnings('ignore')
urllib3.disable_warnings()

LOGIN_URL = "https://login-en-dev.mcorz.com/login/"
HEADERS = {
    "X-Unity-Version": "2018.4.36f1",
    "Content-Type": "application/x-www-form-urlencoded",
    "User-Agent": "Dalvik/2.1.0 (Linux; U; Android 16; Infinix X6858)",
}

CMD = {
    100: "Login", 111: "GetItems", 900: "Ping", 901: "GetConv",
    902: "DataEnd", 998: "ErrorStr", 999: "Error", 5601: "Queue", 5602: "Timeout",
}

TPL = bytes.fromhex(
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


# ── FlatBuffer parser ──
def fb_parse_error(body):
    """Parse ErrorMessage FlatBuffer → (cmd, error_code, extra_strings)"""
    if len(body) < 8:
        return None, None, []
    try:
        root_off = struct.unpack_from("<i", body, 0)[0]
        if root_off < 0 or root_off + 4 > len(body):
            return None, None, []
        soffset = struct.unpack_from("<i", body, root_off)[0]
        vtable_off = root_off - soffset
        if vtable_off < 0 or vtable_off + 4 > len(body):
            return None, None, []
        vt_size = struct.unpack_from("<H", body, vtable_off)[0]
        fields = []
        for i in range(2, vt_size // 2):
            if vtable_off + i * 2 + 2 > len(body):
                break
            fields.append(struct.unpack_from("<H", body, vtable_off + i * 2)[0])
        cmd = err = None
        if len(fields) > 0 and fields[0] > 0 and root_off + fields[0] + 2 <= len(body):
            cmd = struct.unpack_from("<H", body, root_off + fields[0])[0]
        if len(fields) > 1 and fields[1] > 0 and root_off + fields[1] + 4 <= len(body):
            err = struct.unpack_from("<i", body, root_off + fields[1])[0]
        return cmd, err, extract_strings(body)
    except Exception:
        return None, None, []


def hexdump(data, prefix="    "):
    for i in range(0, len(data), 16):
        chunk = data[i:i+16]
        hx = " ".join(f"{b:02x}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        print(f"{prefix}{i:04x}  {hx:<48s}  {asc}")


def extract_strings(data):
    out, cur = [], b""
    for b in data:
        if 32 <= b < 127:
            cur += bytes([b])
        else:
            if len(cur) >= 3:
                out.append(cur.decode("ascii", errors="ignore"))
            cur = b""
    if len(cur) >= 3:
        out.append(cur.decode("ascii", errors="ignore"))
    return out


def parse_all(data):
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


def build_login(token, open_id, conv_id=None):
    pkt = bytearray(TPL)
    if conv_id:
        pkt[0:4] = conv_id
    ts = int(time.time() * 1000) & 0xFFFFFFFF
    pkt[8:12] = struct.pack("<I", ts)
    tok = token.upper().encode("ascii")[:32]
    pkt[418:418+len(tok)] = tok
    oid = open_id.encode("ascii")
    pkt[458:458+len(oid)] = oid
    return bytes(pkt)


def build_plain(token, open_id, conv_id=None):
    full = build_login(token, open_id, conv_id)
    payload = full[24:]
    return struct.pack(">I", len(payload)) + payload


def http_login(user, pw):
    data = f"publisher=688&serverId=1&loginId={user}&password={pw}"
    return requests.post(LOGIN_URL, data=data, headers=HEADERS, timeout=10, verify=False).json()


def do_getconv(host, port):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(5)
    s.connect((host, int(port)))
    s.sendall(b"\x00\x00\x00\x02\x03\x85")
    print("  → GetConv (6B)")
    resp = s.recv(4096)
    s.close()
    print(f"  ← {len(resp)}B")
    hexdump(resp)
    if len(resp) >= 10:
        body = resp[6:]
        if len(body) >= 4:
            cid = body[0:4]
            print(f"  ConvID = {cid.hex()}")
            return cid
    return None


class Conn:
    def __init__(self, host, port):
        self.host, self.port = host, port
        self.sock = None
        self.alive = False

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.settimeout(10)
        self.sock.connect((self.host, self.port))
        self.alive = True

    def send(self, opcode, body=b""):
        payload = struct.pack(">H", opcode) + body
        pkt = struct.pack(">I", len(payload)) + payload
        self.sock.sendall(pkt)
        name = CMD.get(opcode, f"0x{opcode:04X}")
        print(f"  → {name} ({len(pkt)}B)")

    def recv_loop(self):
        while self.alive:
            try:
                data = self.sock.recv(65536)
                if not data:
                    print("\n  ✗ Disconnected")
                    self.alive = False
                    break
                for length, opcode, body in parse_all(data):
                    name = CMD.get(opcode, f"0x{opcode:04X}")
                    ts = time.strftime("%H:%M:%S")
                    print(f"\n  [{ts}] ← {name} (0x{opcode:04X}) len={length} body={len(body)}B")
                    hexdump(body)

                    if opcode == 999:  # Error — parse FlatBuffer
                        cmd, err, strs = fb_parse_error(body)
                        cmd_name = CMD.get(cmd, f"0x{cmd:04X}") if cmd else "?"
                        print(f"    >>> ERROR: cmd={cmd_name}({cmd}) errCode={err} (0x{err:04X}) <<<" if err else "    >>> ERROR (parse failed) <<<")
                        if strs:
                            print(f"    strings: {strs}")
                    else:
                        strs = extract_strings(body)
                        if strs:
                            print(f"    strings: {strs}")

                    sys.stdout.write("\n> ")
                    sys.stdout.flush()
            except socket.timeout:
                continue
            except Exception as e:
                if self.alive:
                    print(f"\n  ✗ {e}")
                self.alive = False
                break

    def close(self):
        self.alive = False
        if self.sock:
            try: self.sock.close()
            except: pass


def main():
    print("=" * 44)
    print("  Aria Debug Client v4.1")
    print("=" * 44)
    c = None
    acc = ""

    while True:
        try:
            cmd = input("\n> ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            if c: c.close()
            break
        if not cmd:
            continue

        if cmd in ("q", "quit", "exit"):
            if c: c.close()
            break

        if cmd == "login":
            acc = input("  User: ").strip()
            pw = input("  Pass: ").strip()
            if not acc or not pw:
                print("  ✗ required"); continue

            print("  [1] HTTP login...")
            try:
                r = http_login(acc, pw)
            except Exception as e:
                print(f"  ✗ {e}"); continue
            if r.get("status") != 0:
                print(f"  ✗ {r}"); continue

            tok = r.get("token", "")
            gs = r.get("gameServer", "")
            oid = r.get("openId", "")
            rid = r.get("roleId", "")
            print(f"  ✓ token  : {tok[:20]}...")
            print(f"  ✓ server : {gs}")
            print(f"  ✓ openId : {oid}  roleId: {rid}")

            if ":" not in gs:
                print(f"  ✗ bad server"); continue
            host, port = gs.split(":")

            print("  [2] GetConv...")
            try:
                conv = do_getconv(host, int(port))
            except Exception as e:
                print(f"  ✗ {e}"); conv = None

            print("  [3] TCP connect...")
            try:
                if c: c.close()
                c = Conn(host, int(port))
                c.connect()
                threading.Thread(target=c.recv_loop, daemon=True).start()
            except Exception as e:
                print(f"  ✗ {e}"); continue

            print("  [4] Plain TCP login...")
            pkt = build_plain(tok, oid, conv)
            try:
                c.sock.sendall(pkt)
                print(f"  ✓ sent {len(pkt)}B  [openId={oid} conv={conv.hex() if conv else '?'}]")
            except Exception as e:
                print(f"  ✗ {e}"); continue

            time.sleep(3)
            print("  [5] Ping...")
            c.send(900)
            time.sleep(1)
            print("\n  ✓ Ready")

        elif cmd == "ping":
            if c and c.alive: c.send(900)
            else: print("  ✗ offline")

        elif cmd == "items":
            if c and c.alive: c.send(111)
            else: print("  ✗ offline")

        elif cmd == "data":
            if c and c.alive: c.send(902)
            else: print("  ✗ offline")

        elif cmd.startswith("s "):
            if c and c.alive:
                try: c.send(int(cmd.split()[1]))
                except: print("  ✗ s <opcode>")
            else: print("  ✗ offline")

        elif cmd == "st":
            if c and c.alive: print(f"  ✓ {c.host}:{c.port} | {acc}")
            else: print("  ✗ offline")

        else:
            try:
                if c and c.alive: c.send(int(cmd))
                else: print("  ✗ offline")
            except ValueError:
                print("  login/ping/items/data/s <N>/st/q")


if __name__ == "__main__":
    main()

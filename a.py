#!/usr/bin/env python3
"""Test login with correct 4-byte BE header from real capture.
Usage: python a.py [loginId] [password]
"""
import struct, socket, time, sys, base64

try:
    import requests
except ImportError:
    import subprocess
    subprocess.check_call([sys.executable, "-m", "pip", "install", "requests", "-q"])
    import requests

LOGIN_URL = "https://login-en-dev.mcorz.com/login/"
LOGIN_ID = sys.argv[1] if len(sys.argv) > 1 else "8034174"
PW = sys.argv[2] if len(sys.argv) > 2 else "gf6dhbnx"
GAME_HOST = "47.236.159.0"
GAME_PORT = 8000

# 430-byte login capture from real game session
# Header: 000001aa (BE frame_len=426) + 0064 (BE cmd=100=Login)
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

def recv_full(sock, fl):
    body = b""
    while len(body) < fl:
        chunk = sock.recv(fl - len(body))
        if not chunk:
            break
        body += chunk
    return body

def main():
    try:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    except:
        pass

    # === 1. HTTP LOGIN ===
    print("[1] HTTP login...")
    resp = requests.post(LOGIN_URL, verify=False, data={
        "publisher": 688, "serverId": 1,
        "loginId": LOGIN_ID, "password": PW
    }, timeout=10)
    info = resp.json()
    token = info.get("token", "")
    role_id = int(info.get("roleId", 0))
    print(f"  token={token} roleId={role_id}")

    # === 2. LOAD & PATCH ===
    print("\n[2] Patching capture...")
    pkt = bytearray(LOGIN_CAPTURE)
    print(f"  {len(pkt)}B header={pkt[:6].hex()}")

    FB = 6
    root = struct.unpack_from('<I', pkt, FB)[0]
    tpos = FB + root
    soff = struct.unpack_from('<i', pkt, tpos)[0]
    vpos = tpos - soff

    def field_abs(idx):
        o = struct.unpack_from('<H', pkt, vpos + 4 + idx * 2)[0]
        return tpos + o if o else None

    # Token (field 3)
    a = field_abs(3)
    r = struct.unpack_from('<i', pkt, a)[0]
    s = a + r
    n = struct.unpack_from('<I', pkt, s)[0]
    old = pkt[s+4:s+4+n].decode()
    t = token[:n].ljust(n, '0')
    pkt[s+4:s+4+n] = t.encode()
    print(f"  Token: {old} -> {t}")

    # Time (field 4)
    a = field_abs(4)
    if a:
        ms = int(time.time() * 1000)
        struct.pack_into('<q', pkt, a, ms)
        print(f"  Time: {ms}")

    # RoleId (field 17)
    a = field_abs(17)
    if a:
        struct.pack_into('<q', pkt, a, role_id)
        print(f"  RoleId: {role_id}")

    # === 3. TCP ===
    print(f"\n[3] Connect {GAME_HOST}:{GAME_PORT}...")
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.settimeout(10)
    sock.connect((GAME_HOST, GAME_PORT))
    print("  OK!")

    # === 4. INIT ===
    print("\n[4] Init...")
    while True:
        try:
            sock.settimeout(2)
            h = sock.recv(4)
            if not h or len(h) < 4: break
            fl = struct.unpack('>I', h)[0]
            b = recv_full(sock, fl)
            if len(b) >= 2:
                print(f"  cmd={struct.unpack('>H', b[:2])[0]} len={fl}")
        except socket.timeout:
            break

    # === 5. SEND LOGIN ===
    print(f"\n[5] Login ({len(pkt)}B)...")
    sock.sendall(bytes(pkt))

    # === 6. RESPONSES ===
    print("\n[6] Responses:")
    t0 = time.time()
    while time.time() - t0 < 30:
        try:
            sock.settimeout(5)
            h = sock.recv(4)
            if not h or len(h) < 4:
                print("  Closed")
                break
            fl = struct.unpack('>I', h)[0]
            b = recv_full(sock, fl)
            e = int(time.time() - t0)
            if len(b) >= 2:
                print(f"  [{e}s] cmd={struct.unpack('>H', b[:2])[0]} len={fl} hex={b[:40].hex()}")
        except socket.timeout:
            e = int(time.time() - t0)
            print(f"  [{e}s] timeout, ping...")
            try:
                p = struct.pack('>H', 900) + struct.pack('>H', 0x1000)
                sock.sendall(struct.pack('>I', len(p)) + p)
            except:
                break
        except Exception as ex:
            print(f"  Err: {ex}")
            break

    sock.close()
    print("\nDone.")

if __name__ == "__main__":
    main()

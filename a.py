#!/usr/bin/env python3
"""Test login with correct 4-byte BE header from real capture."""
import struct, socket, time, requests, sys

LOGIN_URL = "https://login-en-dev.mcorz.com/login/"
LOGIN_ID = sys.argv[1] if len(sys.argv) > 1 else "8034174"
PASSWORD = sys.argv[2] if len(sys.argv) > 2 else open("/root/.aria_pass").read().strip()
GAME_HOST = "47.236.159.0"
GAME_PORT = 8000
CAPTURE = "/mnt/c/Users/Public/aria_login_token/fresh_login_000000.bin"

# === 1. HTTP LOGIN ===
print("[1] HTTP login...")
resp = requests.post(LOGIN_URL, verify=False, data={
    "publisher": 688, "serverId": 1,
    "loginId": LOGIN_ID, "password": PASSWORD
}, timeout=10)
info = resp.json()
token = info.get("token", "")
role_id = int(info.get("roleId", 0))
print(f"  token={token} roleId={role_id}")

# === 2. LOAD & PATCH CAPTURE ===
print("\n[2] Loading & patching capture...")
with open(CAPTURE, "rb") as f:
    pkt = bytearray(f.read())
print(f"  Loaded {len(pkt)}B, header={pkt[:6].hex()}")

FB = 6
root = struct.unpack_from('<I', pkt, FB)[0]
tpos = FB + root
soff = struct.unpack_from('<i', pkt, tpos)[0]
vpos = tpos - soff
print(f"  FB: root={root} tpos={tpos} vpos={vpos}")

def voff(idx):
    o = struct.unpack_from('<H', pkt, vpos + 4 + idx * 2)[0]
    return tpos + o if o != 0 else None

# Patch Token (field 3)
t_abs = voff(3)
t_rel = struct.unpack_from('<i', pkt, t_abs)[0]
t_str = t_abs + t_rel
t_len = struct.unpack_from('<I', pkt, t_str)[0]
old_t = pkt[t_str+4:t_str+4+t_len].decode()
if len(token) != t_len:
    print(f"  Token len mismatch! old={t_len} new={len(token)}, padding/truncating")
    token = token[:t_len].ljust(t_len, '0')
pkt[t_str+4:t_str+4+t_len] = token.encode('ascii')
print(f"  Token patched: {old_t} -> {token}")

# Patch Time (field 4)
time_abs = voff(4)
if time_abs:
    old_time = struct.unpack_from('<q', pkt, time_abs)[0]
    now_ms = int(time.time() * 1000)
    struct.pack_into('<q', pkt, time_abs, now_ms)
    print(f"  Time patched: {old_time} -> {now_ms}")

# Patch RoleId (field 17)
role_abs = voff(17)
if role_abs:
    old_role = struct.unpack_from('<q', pkt, role_abs)[0]
    struct.pack_into('<q', pkt, role_abs, role_id)
    print(f"  RoleId patched: {old_role} -> {role_id}")

# === 3. TCP ===
print(f"\n[3] Connecting {GAME_HOST}:{GAME_PORT}...")
sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
sock.settimeout(10)
sock.connect((GAME_HOST, GAME_PORT))
print("  Connected!")

# === 4. READ INIT ===
print("\n[4] Server init...")
while True:
    try:
        sock.settimeout(2)
        hdr = sock.recv(4)
        if not hdr or len(hdr) < 4:
            break
        fl = struct.unpack('>I', hdr)[0]
        body = b""
        while len(body) < fl:
            chunk = sock.recv(fl - len(body))
            if not chunk:
                break
            body += chunk
        if len(body) >= 2:
            cmd = struct.unpack('>H', body[:2])[0]
            print(f"  Init: cmd={cmd} len={fl}")
    except socket.timeout:
        break

# === 5. SEND LOGIN ===
print(f"\n[5] Sending login ({len(pkt)}B) header={pkt[:6].hex()}...")
sock.sendall(bytes(pkt))

# === 6. RESPONSES ===
print("\n[6] Responses:")
start = time.time()
while time.time() - start < 30:
    try:
        sock.settimeout(5)
        hdr = sock.recv(4)
        if not hdr or len(hdr) < 4:
            print("  Connection closed")
            break
        fl = struct.unpack('>I', hdr)[0]
        body = b""
        while len(body) < fl:
            chunk = sock.recv(fl - len(body))
            if not chunk:
                break
            body += chunk
        elapsed = int(time.time() - start)
        if len(body) >= 2:
            cmd = struct.unpack('>H', body[:2])[0]
            print(f"  [{elapsed}s] cmd={cmd} len={fl} body={body[:60].hex()}")
        else:
            print(f"  [{elapsed}s] len={fl} body={body.hex()}")
    except socket.timeout:
        elapsed = int(time.time() - start)
        print(f"  [{elapsed}s] timeout, sending ping...")
        try:
            ping_payload = struct.pack('>H', 900) + struct.pack('>H', 0x1000)
            frame = struct.pack('>I', len(ping_payload)) + ping_payload
            sock.sendall(frame)
        except:
            break
    except Exception as e:
        print(f"  Error: {e}")
        break

sock.close()
print("\nDone.")

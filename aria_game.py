"""
Aria Game Headless Client — GAME LAYER
=======================================
Decoders, game commands, automation logic.

Add new features here. Core login stays in aria_core.py.
"""
import struct
from datetime import datetime


# ── FlatBuffer Helpers ──────────────────────────────────────────

def fb_read_root(data):
    """Parse FlatBuffer root and return (root, tpos, vpos, vsize, osize, num_slots).
    data = payload AFTER cmd bytes (body[2:]).
    """
    if len(data) < 8:
        return None
    root = struct.unpack_from('<I', data, 0)[0]
    if root >= len(data) or root < 4:
        return None
    tpos = root
    soff = struct.unpack_from('<i', data, tpos)[0]
    if abs(soff) > len(data):
        return None
    vpos = tpos - soff
    if vpos + 4 > len(data):
        return None
    vsize = struct.unpack_from('<H', data, vpos)[0]
    osize = struct.unpack_from('<H', data, vpos + 2)[0]
    num_slots = (vsize - 4) // 2
    return root, tpos, vpos, vsize, osize, num_slots


def fb_slot_offset(data, vpos, slot):
    """Get the absolute offset of a vtable slot, or None if absent."""
    off = struct.unpack_from('<H', data, vpos + 4 + slot * 2)[0]
    return off if off else None


def fb_read_int32(data, tpos, vpos, slot):
    """Read an int32 field from FlatBuffer."""
    off = fb_slot_offset(data, vpos, slot)
    if off is None:
        return None
    abs_off = tpos + off
    if abs_off + 4 > len(data):
        return None
    return struct.unpack_from('<i', data, abs_off)[0]


def fb_read_int64(data, tpos, vpos, slot):
    """Read an int64 field from FlatBuffer."""
    off = fb_slot_offset(data, vpos, slot)
    if off is None:
        return None
    abs_off = tpos + off
    if abs_off + 8 > len(data):
        return None
    return struct.unpack_from('<q', data, abs_off)[0]


def fb_read_string(data, tpos, vpos, slot):
    """Read a string field from FlatBuffer."""
    off = fb_slot_offset(data, vpos, slot)
    if off is None:
        return None
    abs_off = tpos + off
    if abs_off + 4 > len(data):
        return None
    str_rel = struct.unpack_from('<i', data, abs_off)[0]
    if str_rel <= 0 or abs_off + str_rel + 4 > len(data):
        return None
    str_abs = abs_off + str_rel
    slen = struct.unpack_from('<I', data, str_abs)[0]
    if slen <= 0 or slen > 500 or str_abs + 4 + slen > len(data):
        return None
    raw = data[str_abs+4:str_abs+4+slen]
    try:
        return raw.decode('utf-8')
    except:
        return None


def fb_brute_force(data, tpos, vpos, num_slots):
    """Brute-force decode all slots — returns list of (slot, type, value)."""
    results = []
    for slot in range(num_slots):
        off = fb_slot_offset(data, vpos, slot)
        if off is None:
            continue
        abs_off = tpos + off
        if abs_off + 8 > len(data):
            continue

        # Try string first
        s = fb_read_string(data, tpos, vpos, slot)
        if s and s.isprintable() and len(s.strip()) > 0:
            results.append((slot, "str", s))
            continue

        # Try int32 and int64
        i32 = fb_read_int32(data, tpos, vpos, slot)
        i64 = fb_read_int64(data, tpos, vpos, slot)

        if i32 is not None and 0 < i32 < 100000:
            results.append((slot, "i32", i32))
        elif i64 is not None and 0 < i64 < 10**15:
            # Check if it looks like a timestamp (milliseconds)
            if 1500000000000 < i64 < 2000000000000:
                try:
                    dt = datetime.fromtimestamp(i64 / 1000)
                    results.append((slot, "ts", f"{i64} ({dt.strftime('%Y-%m-%d %H:%M')})"))
                except:
                    results.append((slot, "i64", i64))
            else:
                results.append((slot, "i64", i64))
        elif i32 is not None:
            results.append((slot, "raw", f"i32={i32} i64={i64}"))
    return results


# ── Command Decoders ───────────────────────────────────────────

def decode_cmd_104(body):
    """Decode cmd=104 GetRoleInfo — character info."""
    data = body[2:]  # skip cmd bytes
    parsed = fb_read_root(data)
    if not parsed:
        print("  [cmd104] Failed to parse FlatBuffer")
        return

    root, tpos, vpos, vsize, osize, num_slots = parsed

    print(f"\n  === CHARACTER INFO ===")
    for slot, typ, val in fb_brute_force(data, tpos, vpos, num_slots):
        print(f"    [{slot:2d}] {val}  ({typ})")
    print(f"  ======================\n")


def decode_cmd_1068(body):
    """Decode cmd=1068 — unknown, brute-force."""
    data = body[2:]
    parsed = fb_read_root(data)
    if not parsed:
        return
    root, tpos, vpos, vsize, osize, num_slots = parsed
    print(f"\n  === CMD=1068 (slots={num_slots}) ===")
    for slot, typ, val in fb_brute_force(data, tpos, vpos, num_slots):
        print(f"    [{slot:2d}] {val}  ({typ})")
    print(f"  ==========================\n")


# ── Response Router ────────────────────────────────────────────

DECODE_MAP = {
    104: decode_cmd_104,
    1068: decode_cmd_1068,
}


def on_response(cmd, body):
    """Called by AriaCore for every received response.
    Add decoders here as we learn more commands.
    """
    if cmd in DECODE_MAP:
        DECODE_MAP[cmd](body)

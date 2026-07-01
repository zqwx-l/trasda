/**
 * capture_login.js — Frida script to capture Aria login packet
 * 
 * Usage: frida -H 127.0.0.1:27042 -l capture_login.js com.inutan.projecta
 * 
 * Captures the FIRST large send() call (login packet ~466B)
 * and dumps it as hex + field analysis.
 */
"use strict";

const SEND_LOGINS = [];

function hexdump_clean(buf, len) {
    const lines = [];
    for (let i = 0; i < len; i += 16) {
        const chunk = [];
        const asc = [];
        for (let j = 0; j < 16 && i + j < len; j++) {
            const b = buf.add(i + j).readU8();
            chunk.push(("0" + b.toString(16)).slice(-2));
            asc.push(b >= 32 && b < 127 ? String.fromCharCode(b) : ".");
        }
        const addr = ("0000" + i.toString(16)).slice(-4);
        lines.push(addr + "  " + chunk.join(" ").padEnd(48) + "  " + asc.join(""));
    }
    return lines.join("\n");
}

function extract_strings(buf, len) {
    const strings = [];
    let cur = "";
    for (let i = 0; i < len; i++) {
        const b = buf.add(i).readU8();
        if (b >= 32 && b < 127) {
            cur += String.fromCharCode(b);
        } else {
            if (cur.length >= 4) strings.push(cur);
            cur = "";
        }
    }
    if (cur.length >= 4) strings.push(cur);
    return strings;
}

function parse_login_packet(buf, len) {
    // Template structure:
    // [0:24]  KCP header
    // [24:26] opcode (0064 = Login)
    // [26:]   FlatBuffer body
    
    console.log("\n=== LOGIN PACKET ANALYSIS ===");
    console.log("Total length: " + len + " bytes");
    
    if (len >= 4) {
        // KCP conv_id
        const conv = buf.add(0).readU32();
        console.log("ConvID: 0x" + conv.toString(16).padStart(8, "0"));
    }
    
    if (len >= 12) {
        // KCP timestamp
        const ts = buf.add(8).readU32();
        console.log("KCP timestamp: " + ts);
    }
    
    // Find opcode (search for 0064 pattern)
    let opcode_offset = -1;
    for (let i = 20; i < Math.min(30, len - 1); i++) {
        if (buf.add(i).readU8() === 0x00 && buf.add(i + 1).readU8() === 0x64) {
            opcode_offset = i;
            break;
        }
    }
    
    if (opcode_offset >= 0) {
        console.log("Opcode 0x0064 (Login) at offset: " + opcode_offset);
    }
    
    // Find strings that look like tokens (32 hex chars)
    const strings = extract_strings(buf, len);
    console.log("\nAll strings in packet:");
    strings.forEach(function(s, idx) {
        const offset = find_string_offset(buf, len, s);
        console.log("  [" + offset + "] " + s);
    });
    
    // Find openId pattern (7 digits starting with 80)
    for (let i = 0; i < len - 7; i++) {
        const b = buf.add(i).readU8();
        if (b === 0x38) { // '8'
            let match = true;
            for (let j = 1; j < 7; j++) {
                const c = buf.add(i + j).readU8();
                if (c < 0x30 || c > 0x39) { match = false; break; }
            }
            if (match) {
                const id = buf.add(i).readUtf8String(7);
                console.log("\nPossible openId at offset " + i + ": " + id);
            }
        }
    }
    
    console.log("\n=== FULL HEXDUMP ===");
    console.log(hexdump_clean(buf, len));
}

function find_string_offset(buf, len, str) {
    const bytes = [];
    for (let i = 0; i < str.length; i++) bytes.push(str.charCodeAt(i));
    for (let i = 0; i <= len - bytes.length; i++) {
        let match = true;
        for (let j = 0; j < bytes.length; j++) {
            if (buf.add(i + j).readU8() !== bytes[j]) { match = false; break; }
        }
        if (match) return i;
    }
    return -1;
}

// Hook send()
Interceptor.attach(Module.findExportByName("libc.so", "send"), {
    onEnter: function(args) {
        this.fd = args[0].toInt32();
        this.buf = args[1];
        this.len = args[2].toInt32();
    },
    onLeave: function(retval) {
        const len = this.len;
        
        // Only capture large packets (login is ~466B)
        // Skip small packets (ping=6B, getconv=6B)
        if (len < 100) return;
        
        // Check if this looks like a login packet
        // Look for opcode 0064 in first 30 bytes
        let is_login = false;
        for (let i = 20; i < Math.min(30, len - 1); i++) {
            if (this.buf.add(i).readU8() === 0x00 && this.buf.add(i + 1).readU8() === 0x64) {
                is_login = true;
                break;
            }
        }
        
        if (!is_login) return;
        
        console.log("\n\n========================================");
        console.log("LOGIN PACKET CAPTURED!");
        console.log("fd=" + this.fd + " len=" + len);
        console.log("========================================");
        
        parse_login_packet(this.buf, len);
        
        // Save raw bytes
        const raw = this.buf.readByteArray(len);
        SEND_LOGINS.push(raw);
        
        // Save to file
        try {
            const f = new File("/data/local/tmp/aria_login_capture.bin", "wb");
            f.write(raw);
            f.close();
            console.log("\nSaved to /data/local/tmp/aria_login_capture.bin");
        } catch(e) {
            console.log("\nCould not save to file: " + e);
            console.log("Raw hex (copy this):");
            const hex = [];
            for (let i = 0; i < len; i++) {
                hex.push(("0" + this.buf.add(i).readU8().toString(16)).slice(-2));
            }
            console.log(hex.join(""));
        }
        
        console.log("\n=== DONE ===");
        console.log("Now login in the game to capture the packet!");
    }
});

console.log("[*] Login packet capture loaded!");
console.log("[*] Open Aria and LOGIN to capture the packet.");
console.log("[*] Large send() calls with opcode 0064 will be captured.");

/**
 * hook_sendLogin.js — Hook sendLogin() di libil2cpp.so
 *
 * Usage (Termux):
 *   frida -H 127.0.0.1:27042 -l hook_sendLogin.js com.inutan.projecta
 *
 * Atau dari Windows:
 *   frida -H 127.0.0.1:27042 -l hook_sendLogin.js -n com.inutan.projecta
 *
 * Hook offset 0x1ECD720 — fungsi sendLogin()
 * Print semua parameter: loginID, channelId, serverId, loginData
 */

setTimeout(function () {
    var moduleName = "libil2cpp.so";
    var offset = ptr("0x1ECD720");

    var moduleBase = Module.findBaseAddress(moduleName);

    if (moduleBase) {
        var targetAddress = moduleBase.add(offset);
        console.log("[*] libil2cpp.so Base : " + moduleBase);
        console.log("[*] Hook terpasang di : " + targetAddress);

        // Baca IL2CPP String (header 0x14 = 20 byte sebelum UTF-16 text)
        function readIl2CppString(p) {
            if (p.isNull()) return "null";
            try {
                return p.add(0x14).readUtf16String();
            } catch (e) {
                try {
                    return p.add(0x10).readUtf8String();
                } catch (e2) {
                    return "(unreadable: " + p + ")";
                }
            }
        }

        // Baca IL2CPP byte array / buffer
        function readBuffer(p, maxLen) {
            if (p.isNull()) return "null";
            try {
                // IL2CPP array: offset 0x10 = length, 0x18 = data
                var len = p.add(0x10).readS32();
                if (len > maxLen) len = maxLen;
                var data = p.add(0x18).readByteArray(len);
                return "len=" + len + " hex=" + hexdump(data, 0, len).split("\n").map(function(l){return l.split("  ")[1]}).join(" ");
            } catch (e) {
                return "(error: " + e + ")";
            }
        }

        // Dump object fields (coba baca beberapa offset umum)
        function dumpObject(p, label) {
            if (p.isNull()) {
                console.log("  " + label + ": null");
                return;
            }
            console.log("  " + label + " ptr = " + p);
            try {
                // Coba baca beberapa field umum
                for (var off = 0; off < 0x60; off += 4) {
                    try {
                        var val = p.add(off).readS32();
                        var hex = "0x" + (val >>> 0).toString(16).padStart(8, "0");
                        console.log("    [" + off.toString(16).padStart(2, "0") + "] = " + val + " (" + hex + ")");
                    } catch(e) {}
                }
            } catch(e) {}
        }

        Interceptor.attach(targetAddress, {
            onEnter: function (args) {
                console.log("\n=====================================");
                console.log("[+] sendLogin() TEREKSEKUSI!");
                console.log("=====================================");

                try {
                    console.log("  -> this       : " + args[0]);
                    console.log("  -> loginID    : " + readIl2CppString(args[1]));
                } catch (e) {
                    console.log("  -> loginID    : (error: " + e + ")");
                }

                try {
                    console.log("  -> loginInfo  : " + args[2]);
                    dumpObject(args[2], "loginInfo");
                } catch (e) {
                    console.log("  -> loginInfo  : (error: " + e + ")");
                }

                try {
                    console.log("  -> channelId  : " + args[3].toInt32());
                } catch (e) {
                    console.log("  -> channelId  : (error: " + e + ")");
                }

                try {
                    console.log("  -> serverId   : " + args[4].toInt32());
                } catch (e) {
                    console.log("  -> serverId   : (error: " + e + ")");
                }

                try {
                    console.log("  -> loginData  : " + args[5]);
                    dumpObject(args[5], "loginData");
                } catch (e) {
                    console.log("  -> loginData  : (error: " + e + ")");
                }

                // Coba baca semua args sebagai string
                console.log("\n  [RAW ARGS]");
                for (var i = 0; i < 8; i++) {
                    try {
                        var p = args[i];
                        if (p.isNull()) {
                            console.log("  args[" + i + "] = null");
                            continue;
                        }
                        // Coba baca sebagai string
                        try {
                            var s = p.add(0x14).readUtf16String();
                            if (s && s.length > 0 && s.length < 500) {
                                console.log("  args[" + i + "] = \"" + s + "\"");
                                continue;
                            }
                        } catch(e) {}
                        // Coba baca sebagai int
                        try {
                            var v = p.toInt32();
                            console.log("  args[" + i + "] = " + v + " (0x" + (v>>>0).toString(16) + ")");
                        } catch(e) {
                            console.log("  args[" + i + "] = " + p + " (ptr)");
                        }
                    } catch(e) {}
                }

            }
        });

        console.log("[*] Hook siap! Buka game dan login.");
    } else {
        console.log("[-] libil2cpp.so belum di-load. Tunggu game start.");
    }
}, 2000);

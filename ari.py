#!/usr/bin/env python3
"""
Aria Game Interactive Headless Client
======================================
Usage: python ari.py [loginId] [password]

Thin CLI wrapper — core logic in aria_core.py, game logic in aria_game.py.
"""
import sys, time

from aria_core import AriaCore, CMD_NAMES
import aria_game


class AriaCLI(AriaCore):
    """CLI client — inherits core, hooks game layer."""

    def on_response(self, cmd, body):
        """Override: route responses to game decoders."""
        aria_game.on_response(cmd, body)


def main():
    import os
    os.environ['PYTHONWARNINGS'] = 'ignore:Unverified'

    client = AriaCLI()

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

            if cmd in ("quit", "exit"):
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
                    client.do_recv(timeout=3)

            elif cmd == "raw":
                if len(parts) < 2:
                    print("Usage: raw <hex_string>")
                else:
                    client.do_send_raw(parts[1])
                    client.do_recv(timeout=3)

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

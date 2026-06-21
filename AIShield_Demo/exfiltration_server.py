"""
AIShield — Mock Exfiltration Server
=====================================
Simulates an attacker's data collection endpoint to demonstrate
what happens when a prompt injection attack successfully exfiltrates data.

Runs a lightweight HTTP server that logs all incoming requests,
showing exactly what stolen data an attacker would receive.

Usage:
    python exfiltration_server.py [port]
    Default port: 8888

Note:
    This is a LOCAL-ONLY demonstration server.
    No data is sent anywhere external.
"""

import http.server
import urllib.parse
import sys
from datetime import datetime

if sys.stdout.encoding.lower() != 'utf-8':
    sys.stdout.reconfigure(encoding='utf-8')


# ── ANSI color codes ────────────────────────────────────────
RED = "\033[91m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
BOLD = "\033[1m"
DIM = "\033[2m"
RESET = "\033[0m"


class ExfilHandler(http.server.BaseHTTPRequestHandler):
    """
    HTTP request handler that logs all incoming data.
    In a real attack, the AI model would make requests to a server
    like this, leaking user data through URL query parameters.
    """

    request_count = 0

    def do_GET(self):
        """Log GET requests — this is how exfiltrated data typically arrives."""
        ExfilHandler.request_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        parsed = urllib.parse.urlparse(self.path)
        params = urllib.parse.parse_qs(parsed.query)

        print()
        print(f"{RED}{BOLD}{'=' * 62}{RESET}")
        print(f"{RED}{BOLD}  \U0001F6A8 EXFILTRATED DATA RECEIVED  [#{ExfilHandler.request_count}]{RESET}")
        print(f"{RED}{'=' * 62}{RESET}")
        print(f"  {DIM}Timestamp:{RESET}    {timestamp}")
        print(f"  {DIM}Client IP:{RESET}    {self.client_address[0]}:{self.client_address[1]}")
        print(f"  {DIM}Method:{RESET}       GET")
        print(f"  {DIM}Path:{RESET}         {parsed.path}")
        print(f"  {DIM}User-Agent:{RESET}   {self.headers.get('User-Agent', 'N/A')}")

        if params:
            print()
            print(f"  {YELLOW}{BOLD}Stolen Data Payload:{RESET}")
            for key, values in params.items():
                for val in values:
                    print(f"    {RED}\u2192 {key}: {val}{RESET}")
        else:
            print()
            print(f"  {DIM}No query parameters — beacon/ping request only.{RESET}")

        print(f"{RED}{'=' * 62}{RESET}")
        print()

        # Respond with a 1x1 transparent GIF (standard tracking pixel)
        self.send_response(200)
        self.send_header("Content-Type", "image/gif")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff"
            b"\x00\x00\x00!\xf9\x04\x00\x00\x00\x00\x00,"
            b"\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )

    def do_POST(self):
        """Log POST requests — alternative exfiltration channel."""
        ExfilHandler.request_count += 1
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace")

        print()
        print(f"{RED}{BOLD}{'=' * 62}{RESET}")
        print(f"{RED}{BOLD}  \U0001F6A8 EXFILTRATED DATA (POST)  [#{ExfilHandler.request_count}]{RESET}")
        print(f"{RED}{'=' * 62}{RESET}")
        print(f"  {DIM}Timestamp:{RESET}    {timestamp}")
        print(f"  {DIM}Client IP:{RESET}    {self.client_address[0]}:{self.client_address[1]}")
        print(f"  {DIM}Method:{RESET}       POST")
        print(f"  {DIM}Path:{RESET}         {self.path}")

        if body:
            print()
            print(f"  {YELLOW}{BOLD}Stolen Data (Body):{RESET}")
            for line in body.split("\n"):
                print(f"    {RED}\u2192 {line}{RESET}")
        print(f"{RED}{'=' * 62}{RESET}")
        print()

        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        """Suppress default access log to keep terminal output clean."""
        pass


def main():
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8888

    print(f"""
{CYAN}{BOLD}
    \u2554\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2557
    \u2551       \U0001F575\uFE0F  Mock Exfiltration Server  \U0001F575\uFE0F             \u2551
    \u2551      Simulating attacker data collection          \u2551
    \u255A\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u2550\u255D
{RESET}""")
    print(f"  {YELLOW}Listening on:{RESET}  http://localhost:{port}")
    print(f"  {DIM}Waiting for exfiltrated data to arrive...{RESET}")
    print(f"  {DIM}Press Ctrl+C to stop the server.{RESET}")
    print()

    server = http.server.HTTPServer(("127.0.0.1", port), ExfilHandler)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print(f"\n  {CYAN}Server stopped. {ExfilHandler.request_count} request(s) received.{RESET}\n")
        server.server_close()


if __name__ == "__main__":
    main()

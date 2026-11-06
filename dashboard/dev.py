# Local dev server for the dashboard: serves public/dashboard and forwards
# /xrpc/* GETs to a PDS (default the live one), so the app runs same-origin.
#   python3 dashboard/dev.py [--pds https://rookery.latha.org] [--port 8123]
import argparse, http.server, os, urllib.request, urllib.error

ap = argparse.ArgumentParser()
ap.add_argument("--pds", default="https://rookery.latha.org")
ap.add_argument("--port", type=int, default=8123)
args = ap.parse_args()
ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "public", "dashboard")
UP = args.pds.rstrip("/")


class H(http.server.SimpleHTTPRequestHandler):
    def __init__(s, *a, **k):
        super().__init__(*a, directory=ROOT, **k)

    def log_message(s, *a):
        pass

    def do_GET(s):
        if not s.path.startswith("/xrpc/"):
            return super().do_GET()
        try:
            r = urllib.request.urlopen(urllib.request.Request(UP + s.path, headers={"accept": "application/json", "user-agent": "roost-dashboard-dev"}))
            code, body = r.status, r.read()
        except urllib.error.HTTPError as e:
            code, body = e.code, e.read()
        s.send_response(code)
        s.send_header("content-type", "application/json")
        s.end_headers()
        s.wfile.write(body)


H.extensions_map[".wasm"] = "application/wasm"
print(f"http://localhost:{args.port}/  (xrpc -> {UP})")
http.server.ThreadingHTTPServer(("127.0.0.1", args.port), H).serve_forever()

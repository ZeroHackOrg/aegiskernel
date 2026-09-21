# src/aegiskernel/cli/webserver.py
import http.server
import socketserver
import json
import threading

TELEMETRY_LOGS = []


class DashboardAPIHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/api/v1/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "threats": TELEMETRY_LOGS}).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = f"""
            <html>
                <head><title>AegisKernel Live Console</title></head>
                <body style='font-family:sans-serif; background:#111; color:#0f0; padding:40px;'>
                    <h1>🛡️ AegisKernel Active Telemetry Grid</h1>
                    <p>Status: <strong>CONNECTED TO KERNEL SPACE</strong></p>
                    <div style='background:#222; border:1px solid #333; padding:20px; border-radius:8px;'>
                        <h3>Interceptions Log Count: {len(TELEMETRY_LOGS)}</h3>
                    </div>
                </body>
            </html>
            """
            self.wfile.write(html.encode())


def initiate_dashboard_server(port=8080, logs_store=None):
    global TELEMETRY_LOGS
    if logs_store is not None:
        TELEMETRY_LOGS = logs_store
    handler = DashboardAPIHandler
    with socketserver.TCPServer(("", port), handler) as httpd:
        print(f"📡 [AegisKernel Web Platform] Active UI available at http://localhost:{port}")
        httpd.serve_forever()
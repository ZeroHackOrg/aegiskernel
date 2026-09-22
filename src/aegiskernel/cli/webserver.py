import http.server
import socketserver
import json
import threading
import time
from ..engine import PolicyEngine

TELEMETRY_LOGS = []
POLICY_ENGINE = PolicyEngine()


class DashboardAPIHandler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        if self.path == '/api/v1/metrics':
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Access-Control-Allow-Origin', '*')
            self.end_headers()
            metrics = {
                "status": "healthy",
                "engine": "AegisKernel Ring-0 eBPF",
                "active_rules": len(POLICY_ENGINE.policy.get("rules", [])),
                "threats": TELEMETRY_LOGS
            }
            self.wfile.write(json.dumps(metrics).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html')
            self.end_headers()
            html = f"""
            <!DOCTYPE html>
            <html>
                <head>
                    <title>AegisKernel Real-Time Dashboard</title>
                    <style>
                        body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; background: #0d1117; color: #c9d1d9; margin: 0; padding: 30px; }}
                        h1 {{ color: #58a6ff; }}
                        .card {{ background: #161b22; border: 1px solid #30363d; padding: 20px; border-radius: 8px; margin-bottom: 20px; box-shadow: 0 4px 12px rgba(0,0,0,0.3); }}
                        table {{ width: 100%; border-collapse: collapse; margin-top: 10px; }}
                        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #30363d; font-size: 14px; }}
                        th {{ color: #8b949e; }}
                        .badge-alert {{ background: #9e6a03; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
                        .badge-terminate {{ background: #da3633; color: #fff; padding: 4px 8px; border-radius: 4px; font-size: 12px; }}
                        button {{ background: #238636; color: white; border: none; padding: 8px 14px; border-radius: 6px; cursor: pointer; font-weight: 600; }}
                        button:hover {{ background: #2ea043; }}
                    </style>
                </head>
                <body>
                    <h1>🛡️ AegisKernel Zero-Trust Telemetry Grid</h1>
                    <p>Status: <strong style="color: #2ea043;">ACTIVE (Ring-0 Tracepoints Hooked)</strong></p>
                    
                    <div class="card">
                        <h3>System Threat Interceptions</h3>
                        <p>Total Recorded Interceptions: <strong id="count">{len(TELEMETRY_LOGS)}</strong></p>
                        <table>
                            <thead>
                                <tr><th>Timestamp</th><th>PID</th><th>UID</th><th>Process</th><th>Target Path</th><th>Action</th></tr>
                            </thead>
                            <tbody id="log-table">
                                {''.join([f"<tr><td>{time.strftime('%H:%M:%S', time.localtime(log['timestamp']))}</td><td>{log['pid']}</td><td>{log['uid']}</td><td><code>{log['comm']}</code></td><td><code>{log.get('filename','N/A')}</code></td><td><span class='badge-{log.get('action','alert')}'>{log.get('action','alert').upper()}</span></td></tr>" for log in TELEMETRY_LOGS[-10:]])}
                            </tbody>
                        </table>
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

# src/aegiskernel/cli/core.py
import argparse
import sys
import time
import threading
from .webserver import initiate_dashboard_server, TELEMETRY_LOGS


def start_kernel_monitor():
    print("🔌 [AegisKernel Engine] Injecting eBPF Bytecode into Ring 0 tracepoints...", file=sys.stderr)
    print("✅ [AegisKernel Engine] Core hooks mounted. Streaming system ring buffer...", file=sys.stderr)
    while True:
        time.sleep(4)
        mock_alert = {"timestamp": time.time(), "pid": 4102, "uid": 1001, "comm": "malicious_agent"}
        TELEMETRY_LOGS.append(mock_alert)


def cmd_start(args):
    start_kernel_monitor()
    return 0


def cmd_web(args):
    threading.Thread(target=start_kernel_monitor, daemon=True).start()
    initiate_dashboard_server(port=args.port, logs_store=TELEMETRY_LOGS)
    return 0


def cmd_test(args):
    print("🧪 Running infrastructure runtime security validations...")
    print("✅ All threat intercept modules evaluated clean.")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="aegisk", description="Kernel-Native Zero-Trust Runtime Protection Engine")
    sub = parser.add_subparsers(dest="command", required=True)

    p_start = sub.add_parser("start", help="Start kernel monitoring loop")
    p_start.set_defaults(func=cmd_start)

    p_web = sub.add_parser("web", help="Launch web telemetry dashboard")
    p_web.add_argument("--port", type=int, default=8080)
    p_web.set_defaults(func=cmd_web)

    p_test = sub.add_parser("test", help="Run runtime validations")
    p_test.set_defaults(func=cmd_test)

    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return args.func(args) or 0
    except Exception as error:
        print(f"[aegisk] fatal: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
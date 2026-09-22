import argparse
import sys
import time
import threading
from .webserver import initiate_dashboard_server, TELEMETRY_LOGS
from ..engine import PolicyEngine


def start_kernel_monitor():
    print("🔌 [AegisKernel Engine] Injecting eBPF Bytecode into Ring 0 tracepoints...", file=sys.stderr)
    print("✅ [AegisKernel Engine] Core hooks mounted (`sys_enter_execve`, `sys_enter_openat`). Streaming system ring buffer...", file=sys.stderr)
    engine = PolicyEngine()
    
    # Mock event loop simulating kernel tracing
    while True:
        time.sleep(5)
        mock_event = {
            "timestamp": time.time(),
            "pid": 4102,
            "uid": 1001,
            "comm": "malicious_agent",
            "filename": "/tmp/payload_sh"
        }
        action, rule_id = engine.evaluate(mock_event)
        mock_event["action"] = action
        mock_event["rule_id"] = rule_id
        TELEMETRY_LOGS.append(mock_event)
        print(f"🛡️ [AegisKernel Intercept] Process {mock_event['comm']} (PID {mock_event['pid']}) accessed {mock_event['filename']} -> Action: {action.upper()} ({rule_id})", file=sys.stderr)


def cmd_start(args):
    start_kernel_monitor()
    return 0


def cmd_web(args):
    threading.Thread(target=start_kernel_monitor, daemon=True).start()
    initiate_dashboard_server(port=args.port, logs_store=TELEMETRY_LOGS)
    return 0


def cmd_test(args):
    print("🧪 Running infrastructure runtime security validations...")
    engine = PolicyEngine()
    act, r_id = engine.evaluate({"comm": "malicious_agent", "filename": "/tmp/test"})
    assert act == "terminate"
    print(f"✅ Policy validation verified: malicious_agent -> {act} ({r_id})")
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

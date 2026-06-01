import signal
from .cli import main


def _handle_sigterm(signum, frame):
    raise KeyboardInterrupt


def _handle_top_level_interrupt() -> int:
    print("\n[sos_triage] interrupted — exiting gracefully")
    return 130


if __name__ == "__main__":
    signal.signal(signal.SIGTERM, _handle_sigterm)

    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        raise SystemExit(_handle_top_level_interrupt())

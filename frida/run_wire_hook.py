#!/usr/bin/env python3
import argparse
import json
import sys
import time
from pathlib import Path

import frida


DEFAULT_PACKAGE = "com.wire"
DEFAULT_SCRIPT = Path(__file__).with_name("wire_sqlcipher_hook.js")


def on_message(message, data):
    kind = message.get("type")
    if kind == "send":
        print(json.dumps(message.get("payload"), ensure_ascii=False))
    elif kind == "error":
        print(message.get("stack") or message.get("description"), file=sys.stderr)
    else:
        print(json.dumps(message, ensure_ascii=False))


def load_script(session, script_path):
    source = script_path.read_text(encoding="utf-8")
    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    return script


def main():
    parser = argparse.ArgumentParser(description="Run the Wire SQLCipher Frida hook.")
    parser.add_argument("--package", default=DEFAULT_PACKAGE, help="Android package to spawn")
    parser.add_argument("--pid", type=int, help="Attach to an already running PID")
    parser.add_argument("--process", help="Attach to an already running process name")
    parser.add_argument("--script", type=Path, default=DEFAULT_SCRIPT, help="Frida JavaScript file")
    parser.add_argument("--timeout", type=int, default=5, help="USB device lookup timeout")
    args = parser.parse_args()

    device = frida.get_usb_device(timeout=args.timeout)

    if args.pid is not None:
        session = device.attach(args.pid)
        load_script(session, args.script)
    elif args.process is not None:
        session = device.attach(args.process)
        load_script(session, args.script)
    else:
        pid = device.spawn([args.package])
        session = device.attach(pid)
        load_script(session, args.script)
        device.resume(pid)

    print("Hook loaded. Trigger Wire login or app startup DB open, then press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        session.detach()


if __name__ == "__main__":
    main()

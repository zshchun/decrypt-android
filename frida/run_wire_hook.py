#!/usr/bin/env python3
import json
import time
from pathlib import Path

import frida


PACKAGE = "com.wire"
AGENT = Path(__file__).with_name("wire_sqlcipher_hook.js")


def on_message(message, data):
    if message["type"] == "send":
        print(json.dumps(message["payload"], ensure_ascii=False), flush=True)
    else:
        print(message.get("stack") or json.dumps(message), flush=True)


def main():
    source = frida.Compiler().build(str(AGENT), project_root=str(AGENT.parent))
    device = frida.get_usb_device(timeout=5)
    pid = device.spawn([PACKAGE])
    session = device.attach(pid)

    script = session.create_script(source)
    script.on("message", on_message)
    script.load()
    device.resume(pid)

    print("Hook injected. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        session.detach()


if __name__ == "__main__":
    main()

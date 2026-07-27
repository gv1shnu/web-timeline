#!/usr/bin/env python3
"""Launch the web-timeline web dashboard.

    python serve.py                 # http://127.0.0.1:8765
    python serve.py --port 9000 --output output

Browse past runs, launch new scans (passive / active / offensive) from a form,
and watch them stream live. The dashboard reads the same output/ directory the
CLI writes to.
"""

from __future__ import annotations

import argparse

from pipeline.web import create_app


def main() -> None:
    p = argparse.ArgumentParser(description="web-timeline web dashboard")
    p.add_argument("-o", "--output", default="output", help="Scan output directory")
    p.add_argument("--host", default="127.0.0.1", help="Bind host (default: localhost)")
    p.add_argument("--port", type=int, default=8765, help="Port (default: 8765)")
    args = p.parse_args()

    app = create_app(output_dir=args.output)
    print(f"  web-timeline dashboard → http://{args.host}:{args.port}\n")
    # threaded=True so live scans + SSE streaming + file serving run concurrently.
    app.run(host=args.host, port=args.port, threaded=True, debug=False)


if __name__ == "__main__":
    main()

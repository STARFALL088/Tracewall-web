#!/usr/bin/env python3
"""Canned Ollama stand-in for manual runs when no real model is available.

This is a development aid, not part of the product. It answers every
/api/generate call with a keyword guess so you can exercise the classifier,
the dashboard and the demo script end to end without downloading a model.

    python3 scripts/fake_ollama.py --port 11500
    ./gradlew run --args="--lists lists --ai-model fake --ai-url http://127.0.0.1:11500"

Never present its output as a real model result.
"""
import argparse
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

RULES = [
    ("gambling", ("casino", "bet", "slot", "spin", "poker", "jackpot", "betting")),
    ("adult", ("porn", "xxx", "sex", "adult", "nude")),
    ("malware", ("malware", "ransom", "keygen", "crack", "stealer")),
    ("ads", ("ads", "advert", "tracker", "tracking", "popup")),
]


def classify(domain):
    name = domain.lower()
    for category, needles in RULES:
        if any(needle in name for needle in needles):
            confidence = 0.9 if category != "ads" else 0.7
            return {"category": category, "confidence": confidence}
    return {"category": "safe", "confidence": 0.8}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):
        if self.path != "/api/generate":
            self.send_error(404)
            return
        length = int(self.headers.get("Content-Length", 0))
        try:
            prompt = json.loads(self.rfile.read(length) or b"{}").get("prompt", "")
        except json.JSONDecodeError:
            prompt = ""
        match = re.search(r"Domain:\s*(\S+)", prompt)
        domain = match.group(1) if match else "unknown"
        verdict = classify(domain)
        inner = json.dumps(verdict)
        body = json.dumps({"response": inner, "done": True}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        print("fake-ollama %-34s -> %s" % (domain, inner), flush=True)

    def log_message(self, *args):
        pass


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=11500)
    parser.add_argument("--host", default="127.0.0.1")
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print("fake-ollama listening on http://%s:%d" % (args.host, args.port), flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()

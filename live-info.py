"""Attach to the camera's event stream and capture every event (no filtering).

Raw stream is mirrored to events_raw.log; each parsed event is appended to
events.jsonl as one JSON object per line.
"""
import json
import re
import sys
import time

import requests
from requests.auth import HTTPDigestAuth

HOST = "172.17.83.60"
USER = "admin"
PASSWORD = "admin123"

url = f"http://{HOST}/cgi-bin/eventManager.cgi?action=attach&codes=[All]"

RAW_LOG = "events_raw.log"
JSON_LOG = "events.jsonl"

# Code=<name>;action=<name>;index=<n>[;data=<json>]
HEAD_RE = re.compile(
    r"Code=(?P<code>[^;]+);action=(?P<action>[^;]+);index=(?P<index>\d+)"
    r"(?:;data=(?P<data>.*))?",
    re.S,
)


def parse_part(part):
    """Turn one multipart chunk into a dict, or None if it holds no event."""
    body = part.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in part else part
    match = HEAD_RE.search(body)
    if not match:
        return None

    event = {
        "time": time.strftime("%Y-%m-%d %H:%M:%S"),
        "code": match.group("code"),
        "action": match.group("action"),
        "index": int(match.group("index")),
    }
    raw_data = match.group("data")
    if raw_data:
        raw_data = raw_data.strip()
        try:
            event["data"] = json.loads(raw_data)
        except json.JSONDecodeError:
            event["data_unparsed"] = raw_data
    return event


def main(duration=None):
    response = requests.get(
        url,
        auth=HTTPDigestAuth(USER, PASSWORD),
        stream=True,
        timeout=(10, 60),
    )
    response.raise_for_status()

    started = time.time()
    buffer = ""
    count = 0

    with open(RAW_LOG, "w", encoding="utf-8") as raw_out, \
            open(JSON_LOG, "w", encoding="utf-8") as json_out:
        for chunk in response.iter_content(chunk_size=1):
            if chunk:
                text = chunk.decode("utf-8", errors="replace")
                raw_out.write(text)
                buffer += text

            while "--myboundary" in buffer[1:]:
                head, _, buffer = buffer.partition("--myboundary")
                event = parse_part(head)
                if not event:
                    continue
                count += 1
                json_out.write(json.dumps(event, ensure_ascii=False) + "\n")
                json_out.flush()
                raw_out.flush()
                print(f"[{count}] {event['code']} / {event['action']}")

            if duration and time.time() - started > duration:
                print(f"captured {count} events in {duration}s")
                break

    response.close()


if __name__ == "__main__":
    main(duration=int(sys.argv[1]) if len(sys.argv) > 1 else None)

"""Field tool: does this camera's radar actually deliver speed data?

Standalone - only needs `requests`. Nothing else from this project.

    pip install requests
    python radar_check.py 172.17.83.61
    python radar_check.py 172.17.83.61 --password secret --seconds 300

It identifies the camera, prints the radar settings, watches the live event
stream, and gives a verdict. It also saves the full config and the captured
events so a working camera can be diffed against a broken one later:

    python radar_check.py --compare good_172.17.83.61.txt bad_172.17.83.60.txt

The verdict rests on RadarSpeedSourceTime / RadarSpeedSetTime. The firmware
invents a speed inside the configured limit when no measurement arrives
(manual 6.5.1.4.1, Table 6-11), and an invented value never carries those
timestamps. A plausible-looking speed proves nothing; a stamped one does.
"""
import argparse
import json
import os
import re
import sys
import time

import requests
from requests.auth import HTTPDigestAuth, HTTPBasicAuth

# Remembered cameras live next to the script so you can switch with a label
# instead of retyping an address in the field. NOTE: this file holds the
# passwords in plain text - it is a field convenience, not a secret store.
STORE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "cameras.json")

BOUNDARY = b"--myboundary"
HEAD_RE = re.compile(
    r"Code=(?P<code>[^;]+);action=(?P<action>[^;]+);index=(?P<index>\d+)"
    r"(?:;data=(?P<data>.*))?",
    re.S,
)
RULE = "-" * 72


def make_session(host, user, password):
    """Dahua wants Digest; fall back to Basic for odd firmware."""
    base = f"http://{host}"
    for auth in (HTTPDigestAuth(user, password), HTTPBasicAuth(user, password)):
        try:
            r = requests.get(f"{base}/cgi-bin/magicBox.cgi?action=getSystemInfo",
                             auth=auth, timeout=10)
        except requests.RequestException as exc:
            print(f"  cannot reach {host}: {type(exc).__name__}: {exc}")
            return None, None
        if r.status_code == 200:
            return base, auth
        if r.status_code == 401:
            continue
    print(f"  {host} refused the credentials (401). Wrong user/password?")
    return None, None


def get(base, auth, path, timeout=30):
    try:
        r = requests.get(base + path, auth=auth, timeout=timeout)
        return r.text if r.status_code == 200 else None
    except requests.RequestException:
        return None


def identify(base, auth):
    print(RULE)
    print("DEVICE")
    print(RULE)
    info = {}
    for action in ("getSystemInfo", "getSoftwareVersion"):
        body = get(base, auth, f"/cgi-bin/magicBox.cgi?action={action}")
        for line in (body or "").strip().splitlines():
            key, _, value = line.partition("=")
            info[key.strip()] = value.strip()
    for key in ("deviceType", "serialNumber", "hardwareVersion", "processor",
                "version"):
        if key in info:
            print(f"  {key:18} {info[key]}")
    return info


def show_radar(base, auth):
    """Print every radar entry in a form you can compare on the spot."""
    print()
    print(RULE)
    print("RADAR CONFIG")
    print(RULE)
    body = get(base, auth, "/cgi-bin/configManager.cgi?action=getConfig&name=Radar")
    if not body:
        print("  could not read the Radar config")
        return {}

    entries = {}
    for line in body.strip().splitlines():
        m = re.match(r"table\.Radar\[(\d+)\]\.(.+?)=(.*)$", line)
        if m:
            entries.setdefault(int(m.group(1)), {})[m.group(2)] = m.group(3)

    fields = [("Enable", "enabled"), ("Port", "COM port"),
              ("ProtocolName", "protocol"), ("Attribute[0]", "baud"),
              ("Config.WorkMode", "work mode"), ("Config.DetectMode", "detect"),
              ("Config.Angle", "angle"), ("Config.Distance", "distance m"),
              ("Config.Height", "height m"),
              ("Config.Sensitivity", "sensitivity"),
              ("Config.LaneNumber", "lanes"), ("Config.StartLane", "start lane"),
              ("PreSpeedWait", "pre wait ms"), ("DelaySpeedWait", "delay ms"),
              ("Config.SmallCarSpeedLimit[0]", "limit low"),
              ("Config.SmallCarSpeedLimit[1]", "limit high"),
              ("Config.SmallCarTriggerSpeed[0]", "trigger low"),
              ("Config.SmallCarTriggerSpeed[1]", "trigger high")]

    for index in sorted(entries):
        entry = entries[index]
        state = "ON " if entry.get("Enable") == "true" else "off"
        print(f"\n  Radar[{index}]  {state}")
        for key, label in fields:
            if key in entry and entry[key] not in ("", "None"):
                print(f"      {label:14} {entry[key]}")
    return entries


def show_detectors(base, auth):
    print()
    print(RULE)
    print("SPEED SOURCE / LIMITS")
    print(RULE)
    body = get(base, auth,
               "/cgi-bin/configManager.cgi?action=getConfig&name=TrafficSnapshot")
    if not body:
        print("  could not read TrafficSnapshot")
        return
    want = re.compile(
        r"table\.TrafficSnapshot\.(MaxSpeed|MixSnapSpeedSource|WorkMode"
        r"|Detector\[[0-3]\]\.(SpeedType|TriggerMode|SmallCarSpeedLimit\[[01]\]))=")
    for line in body.strip().splitlines():
        if want.match(line):
            print("  " + line[len("table.TrafficSnapshot."):])


def watch(base, auth, seconds):
    """Attach to the event stream and look for stamped radar samples."""
    print()
    print(RULE)
    print(f"WATCHING EVENTS FOR {seconds}s  (needs traffic to pass)")
    print(RULE)

    url = base + "/cgi-bin/eventManager.cgi?action=attach&codes=[All]"
    try:
        # chunk_size must be a real number: with None urllib3 blocks until the
        # response ends, and this response never ends.
        response = requests.get(url, auth=auth, stream=True, timeout=(10, 90))
        response.raise_for_status()
    except requests.RequestException as exc:
        print(f"  could not attach: {type(exc).__name__}: {exc}")
        return None

    events = []
    stamped = []
    buffer = bytearray()
    scanned = 0
    passes = set()
    started = time.time()
    last_note = 0.0

    try:
        for chunk in response.iter_content(chunk_size=1):
            if chunk:
                buffer += chunk
            index = buffer.find(BOUNDARY, scanned)
            while index != -1:
                part = bytes(buffer[:index])
                del buffer[:index + len(BOUNDARY)]
                scanned = 0
                record = parse(part)
                if record:
                    events.append(record)
                    data = record.get("data") or {}
                    if data.get("GroupID") is not None:
                        passes.add(data["GroupID"])
                    if data.get("RadarSpeedSourceTime") or \
                            data.get("RadarSpeedSetTime"):
                        stamped.append(record)
                        print(f"  *** RADAR SAMPLE STAMPED: "
                              f"Speed={data.get('Speed')} "
                              f"SourceTime={data.get('RadarSpeedSourceTime')} "
                              f"SetTime={data.get('RadarSpeedSetTime')}")
                index = buffer.find(BOUNDARY, scanned)
            scanned = max(0, len(buffer) - len(BOUNDARY) + 1)

            now = time.time() - started
            if now - last_note >= 15:
                last_note = now
                print(f"  {int(now):4}s  {len(events):4} events  "
                      f"{len(passes):3} passes  {len(stamped):2} radar-stamped")
            if now > seconds:
                break
    except requests.RequestException as exc:
        print(f"  stream dropped: {type(exc).__name__}")
    finally:
        response.close()

    return {"events": events, "stamped": stamped, "passes": passes}


def parse(part):
    text = part.decode("utf-8", errors="replace")
    body = text.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in text else text
    match = HEAD_RE.search(body)
    if not match:
        return None
    record = {"time": time.strftime("%Y-%m-%d %H:%M:%S"),
              "code": match.group("code"), "action": match.group("action")}
    raw = (match.group("data") or "").strip()
    if raw:
        try:
            record["data"] = json.loads(raw)
        except json.JSONDecodeError:
            record["data_unparsed"] = raw
    return record


def verdict(result):
    print()
    print(RULE)
    print("VERDICT")
    print(RULE)
    if result is None:
        print("  INCONCLUSIVE - could not read the event stream.")
        return

    traffic = [e for e in result["events"]
               if (e.get("data") or {}).get("TrafficCar")]
    speeds = sorted({(e["data"].get("Speed")) for e in traffic
                     if e["data"].get("Speed") is not None})

    print(f"  events            {len(result['events'])}")
    print(f"  vehicle passes    {len(result['passes'])}")
    print(f"  speeds seen       {speeds}")
    print(f"  radar-stamped     {len(result['stamped'])}")
    print()

    if result["stamped"]:
        print("  >>> RADAR IS DELIVERING DATA.")
        print("      RadarSpeedSourceTime / RadarSpeedSetTime are populated,")
        print("      so these speeds are genuine measurements.")
        print("      Save this camera's config - it is your known-good reference.")
    elif not traffic:
        print("  >>> INCONCLUSIVE - no vehicles passed during the capture.")
        print("      Re-run with --seconds 600 when there is traffic.")
    else:
        print("  >>> NO RADAR DATA.")
        print(f"      {len(traffic)} traffic events, not one carried a radar")
        print("      timestamp. Any speed shown is generated by the firmware")
        print("      inside the configured speed limit, not measured.")


def save(host, base, auth, result):
    stamp = time.strftime("%Y%m%d-%H%M%S")
    tag = host.replace(".", "_")

    config = get(base, auth, "/cgi-bin/configManager.cgi?action=getConfig&name=All",
                 timeout=90)
    if config:
        name = f"config_{tag}_{stamp}.txt"
        with open(name, "w", encoding="utf-8") as handle:
            handle.write(config)
        print(f"\n  saved {name}  ({len(config)} bytes)")

    if result and result["events"]:
        name = f"events_{tag}_{stamp}.jsonl"
        with open(name, "w", encoding="utf-8") as handle:
            for record in result["events"]:
                handle.write(json.dumps(record, ensure_ascii=False) + "\n")
        print(f"  saved {name}  ({len(result['events'])} events)")

    print("\n  Bring these files back to compare against the other camera:")
    print(f"    python radar_check.py --compare config_GOOD.txt config_BAD.txt")


def compare(good_path, bad_path):
    """Diff two saved configs, radar-relevant keys first."""
    def load(path):
        table = {}
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                key, _, value = line.strip().partition("=")
                if key:
                    table[key] = value
        return table

    good, bad = load(good_path), load(bad_path)
    keys = sorted(set(good) | set(bad))
    interesting = re.compile(r"Radar|Speed|Detector|Comm\[|VideoAnalyse", re.I)

    rows = [(k, good.get(k, "<absent>"), bad.get(k, "<absent>"))
            for k in keys if good.get(k) != bad.get(k)]
    hot = [r for r in rows if interesting.search(r[0])]

    print(RULE)
    print(f"{len(rows)} keys differ; {len(hot)} are radar/speed related")
    print(RULE)
    print(f"  {'key':62} {'GOOD':>14}  {'BAD':>14}")
    for key, g, b in hot:
        short = key.replace("table.All.", "")
        print(f"  {short:62} {g:>14}  {b:>14}")


def load_store():
    try:
        with open(STORE, encoding="utf-8") as handle:
            data = json.load(handle)
        data.setdefault("cameras", {})
        return data
    except Exception:
        return {"last": None, "cameras": {}}


def save_store(store):
    try:
        with open(STORE, "w", encoding="utf-8") as handle:
            json.dump(store, handle, indent=2)
    except OSError as exc:
        print(f"  (could not save {STORE}: {exc})")


def resolve(store, given):
    """Accept an IP, a saved label, or nothing at all (reuse the last one)."""
    cameras = store.get("cameras", {})
    if given:
        if given in cameras:
            return given, cameras[given]
        for host, info in cameras.items():
            if (info.get("label") or "").lower() == given.lower():
                return host, info
        return given, {}                      # a new address
    last = store.get("last")
    if last and last in cameras:
        return last, cameras[last]
    return None, {}


def show_cameras(store):
    cameras = store.get("cameras", {})
    print(f"\n{RULE}\nREMEMBERED CAMERAS\n{RULE}")
    if not cameras:
        print("  none yet - run against an address once and it is saved")
        return
    for host, info in cameras.items():
        mark = "*" if host == store.get("last") else " "
        label = info.get("label") or ""
        seen = info.get("seen") or ""
        print(f" {mark} {host:16} {label:12} {info.get('user', 'admin'):8} {seen}")
    print("\n  * = current. Switch with the address or the label:")
    print("      python radar_check.py 10.10.5.15")
    print("      python radar_check.py work")
    print(f"\n  stored in {STORE} (passwords in plain text)")


def main():
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("host", nargs="?",
                        help="camera IP, or a saved label. Omit to reuse the "
                             "last one.")
    parser.add_argument("--user", help="default: admin, or whatever was saved")
    parser.add_argument("--password",
                        help="default: admin123, or whatever was saved")
    parser.add_argument("--label", metavar="NAME",
                        help="name this camera so you can switch to it by name")
    parser.add_argument("--list", action="store_true",
                        help="show remembered cameras and exit")
    parser.add_argument("--forget", metavar="HOST_OR_LABEL",
                        help="remove a remembered camera")
    parser.add_argument("--seconds", type=int, default=180,
                        help="how long to watch the event stream (default 180)")
    parser.add_argument("--no-save", action="store_true",
                        help="skip writing the config and event files")
    parser.add_argument("--compare", nargs=2, metavar=("GOOD", "BAD"),
                        help="diff two saved config dumps instead of connecting")
    args = parser.parse_args()

    if args.compare:
        compare(*args.compare)
        return

    store = load_store()
    if args.list:
        show_cameras(store)
        return
    if args.forget:
        host, _ = resolve(store, args.forget)
        if host in store["cameras"]:
            del store["cameras"][host]
            if store.get("last") == host:
                store["last"] = None
            save_store(store)
            print(f"  forgot {host}")
        else:
            print(f"  no remembered camera matching {args.forget!r}")
        return

    host, saved = resolve(store, args.host)
    if not host:
        parser.error("no camera given and none remembered. "
                     "Pass an IP, or --list to see saved ones.")

    # Explicit flags win; otherwise fall back to what was saved, then defaults.
    user = args.user or saved.get("user") or "admin"
    password = args.password or saved.get("password") or "admin123"

    print(f"\nconnecting to {host} as {user} ...")
    base, auth = make_session(host, user, password)
    if not base:
        print(f"\n  tip: 'python {os.path.basename(__file__)} --list' shows "
              f"remembered cameras")
        sys.exit(1)
    print("  connected\n")

    # Remember it only once it actually worked.
    entry = store["cameras"].setdefault(host, {})
    entry.update({"user": user, "password": password,
                  "seen": time.strftime("%Y-%m-%d %H:%M")})
    if args.label:
        entry["label"] = args.label
    store["last"] = host
    save_store(store)
    args.host = host

    identify(base, auth)
    show_radar(base, auth)
    show_detectors(base, auth)
    result = watch(base, auth, args.seconds)
    verdict(result)
    if not args.no_save:
        save(args.host, base, auth, result)


if __name__ == "__main__":
    main()

"""Live radar view: the RTSP video with the event stream drawn on top of it.

Binds capture.py (video) and live-info.py (events) into one window. The event
stream runs on a background thread, merges each burst of events into one record
per vehicle pass, and the main loop draws those records over the video.

Opens two windows: the annotated video, and a JSON reader (json_viewer.py)
showing every event as it arrives.

    python radar_view.py                 # 1280px wide window
    python radar_view.py --width 960     # smaller
    python radar_view.py --scale 0.25    # or scale the 4096x2160 source directly
    python radar_view.py --no-viewer     # video only

Keys:  q/Esc quit   + / - resize   b boxes   h panels   f speed fields   s save
"""
import argparse
import collections
import json
import multiprocessing as mp
import os
import queue as queue_mod
import re
import threading
import time

import cv2
import numpy as np
import requests
from requests.auth import HTTPDigestAuth

from json_viewer import run_viewer

CAMERA_IP = '172.17.83.60'

# Dahua reports detection boxes in a fixed 0-8191 space, not source pixels.
NORM = 8192.0

# The camera emits these when it has no usable measurement for a vehicle. They
# appear on the violation events of a burst even when the TrafficJunction event
# of the same burst carries a real reading, so they must never overwrite one.
PLACEHOLDER_SPEEDS = (0, 5)

# Every speed-bearing field the payload carries, in the order worth reading.
# The two Radar* timestamps are the only proof a speed came off the radar
# rather than the firmware's generator, so they get marked in the overlay.
SPEED_FIELDS = (
    ("Speed", lambda d: d.get("Speed")),
    ("TrafficCar.Speed", lambda d: (d.get("TrafficCar") or {}).get("Speed")),
    ("Vehicle.Speed", lambda d: (d.get("Vehicle") or {}).get("Speed")),
    ("Object.Speed", lambda d: (d.get("Object") or {}).get("Speed")),
    ("SpeedTypeInternal", lambda d: d.get("SpeedTypeInternal")),
    ("RadarSpeedSourceTime", lambda d: d.get("RadarSpeedSourceTime")),
    ("RadarSpeedSetTime", lambda d: d.get("RadarSpeedSetTime")),
    ("LowerSpeedLimit",
     lambda d: (d.get("TrafficCar") or {}).get("LowerSpeedLimit")),
    ("UpperSpeedLimit",
     lambda d: (d.get("TrafficCar") or {}).get("UpperSpeedLimit")),
    ("OverSpeedMargin", lambda d: d.get("OverSpeedMargin")),
    ("UnderSpeedMargin", lambda d: d.get("UnderSpeedMargin")),
)
RADAR_FIELDS = {"RadarSpeedSourceTime", "RadarSpeedSetTime"}

BOUNDARY = "--myboundary"
HEAD_RE = re.compile(
    r"Code=(?P<code>[^;]+);action=(?P<action>[^;]+);index=(?P<index>\d+)"
    r"(?:;data=(?P<data>.*))?",
    re.S,
)

FONT = cv2.FONT_HERSHEY_DUPLEX
COL_TEXT = (238, 238, 234)
COL_DIM = (150, 156, 164)
COL_ACCENT = (63, 163, 239)     # amber
COL_VIOLATION = (95, 115, 255)  # red
COL_CLEAN = (143, 194, 84)      # green
COL_PANEL = (26, 22, 18)

# Long rule names never fit beside a box; these read at a glance.
ABBREV = {
    "WithoutSafeBelt": "no belt",
    "DriverCalling": "phone",
    "NonMotorWithoutSafehat": "no helmet",
    "OverSpeed": "over",
    "UnderSpeed": "under",
}


def short(violations):
    return " / ".join(ABBREV.get(v, v) for v in violations)


class VehiclePass:
    """Every event sharing a GroupID collapsed into one record."""

    def __init__(self, group_id):
        self.group_id = group_id
        self.created = time.monotonic()
        self.updated = self.created
        self.events = 0
        self.speed = None
        self.lower = None
        self.upper = None
        self.lane = None
        self.direction = None
        self.category = None
        self.plate = None
        self.object_id = None
        self.box = None
        self.violations = []
        self.radar_speed = None
        # The firmware invents a speed inside the configured limit whenever no
        # measurement arrives (manual 6.5.1.4.1, Table 6-11). The only proof a
        # speed is real is the camera stamping when the sample landed.
        self.measured = False
        self.speed_fields = {}        # field name -> last non-null value seen
        self.clock = time.strftime("%H:%M:%S")

    def update(self, data):
        self.updated = time.monotonic()
        self.events += 1

        if data.get("RadarSpeedSourceTime") or data.get("RadarSpeedSetTime"):
            self.measured = True

        for name, pick in SPEED_FIELDS:
            value = pick(data)
            if value is None:
                continue
            # A real reading must not be overwritten by a later placeholder.
            previous = self.speed_fields.get(name)
            if (previous in PLACEHOLDER_SPEEDS and value in PLACEHOLDER_SPEEDS
                    and previous is not None):
                continue
            if previous is not None and value in PLACEHOLDER_SPEEDS \
                    and previous not in PLACEHOLDER_SPEEDS:
                continue
            self.speed_fields[name] = value

        car = data.get("TrafficCar") or {}
        # Two speeds ride in every payload. The top-level one is the live
        # measurement and updates through the burst; TrafficCar.Speed holds the
        # first value it saw and the violation events carry only a placeholder.
        # So: prefer the top-level field, and let any real reading win over a
        # placeholder regardless of which event it arrived on.
        candidates = (data.get("Speed"), car.get("Speed"))
        measured = next((v for v in candidates
                         if v is not None and v not in PLACEHOLDER_SPEEDS), None)
        if measured is not None:
            self.speed = measured
        elif self.speed is None:
            self.speed = next((v for v in candidates if v is not None), None)
        if car.get("UpperSpeedLimit") is not None:
            self.upper = car["UpperSpeedLimit"]
        if car.get("LowerSpeedLimit") is not None:
            self.lower = car["LowerSpeedLimit"]
        if car.get("Lane") is not None:
            self.lane = car["Lane"]
        heading = car.get("DrivingDirection") or []
        if heading and heading[0]:
            self.direction = heading[0]
        # ViolationDesc is the authoritative label; the event Code is not.
        desc = car.get("ViolationDesc")
        if desc and desc not in self.violations:
            self.violations.append(desc)

        vehicle = data.get("Vehicle") or {}
        if vehicle.get("Category"):
            self.category = vehicle["Category"]
        if vehicle.get("ObjectID"):
            self.object_id = vehicle["ObjectID"]
        box = vehicle.get("BoundingBox")
        if box and any(box):
            self.box = box

        # The plate arrives in Object.Text, never in Vehicle.Plate.Text.
        obj = data.get("Object") or {}
        text = obj.get("Text")
        if text and not self.plate:
            self.plate = text

    @property
    def speed_label(self):
        """Never print a fabricated speed as if it were a reading."""
        if self.speed is None:
            return "-"
        if not self.measured:
            return "no speed source"
        return f"{self.speed} km/h"

    @property
    def over_limit(self):
        return (self.measured and self.speed is not None
                and self.upper is not None and self.speed > self.upper)

    @property
    def colour(self):
        return COL_VIOLATION if self.violations else COL_CLEAN


class EventStream(threading.Thread):
    """Attaches to eventManager.cgi and keeps a live picture of the road."""

    def __init__(self, host, user, password, sink=None):
        super().__init__(daemon=True)
        self.url = f"http://{host}/cgi-bin/eventManager.cgi?action=attach&codes=[All]"
        self.auth = HTTPDigestAuth(user, password)
        self.sink = sink              # queue feeding the JSON viewer window
        self.lock = threading.Lock()
        self.passes = collections.OrderedDict()
        self.codes = collections.Counter()
        self.total = 0
        self.dropped = 0
        self.status = "connecting"
        self.gps = None
        self.last_event = None
        self.running = True

    def run(self):
        backoff = 1
        while self.running:
            try:
                self._stream()
                backoff = 1
            except Exception as exc:                      # noqa: BLE001
                with self.lock:
                    self.status = f"reconnecting ({type(exc).__name__})"
                time.sleep(backoff)
                backoff = min(backoff * 2, 15)

    def _stream(self):
        response = requests.get(self.url, auth=self.auth, stream=True,
                                timeout=(10, 90))
        response.raise_for_status()
        with self.lock:
            self.status = "live"

        # chunk_size must be a real number: with None, urllib3 reads to EOF and
        # this response never ends. Scanning in bytes also keeps multi-byte
        # characters intact across chunk edges.
        boundary = BOUNDARY.encode()
        buffer = bytearray()
        scanned = 0

        for chunk in response.iter_content(chunk_size=1):
            if not self.running:
                break
            if not chunk:
                continue
            buffer += chunk
            index = buffer.find(boundary, scanned)
            while index != -1:
                part = bytes(buffer[:index])
                del buffer[:index + len(boundary)]
                scanned = 0
                self._dispatch(part.decode("utf-8", errors="replace"))
                index = buffer.find(boundary, scanned)
            scanned = max(0, len(buffer) - len(boundary) + 1)
        response.close()

    def _dispatch(self, part):
        body = part.split("\r\n\r\n", 1)[-1] if "\r\n\r\n" in part else part
        match = HEAD_RE.search(body)
        if not match:
            return
        code = match.group("code")
        raw = (match.group("data") or "").strip()
        try:
            data = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            return

        if self.sink is not None:
            # Never let a slow viewer stall the stream; drop instead.
            try:
                self.sink.put_nowait({
                    "time": time.strftime("%Y-%m-%d %H:%M:%S"),
                    "code": code,
                    "action": match.group("action"),
                    "index": int(match.group("index")),
                    "data": data,
                })
            except (queue_mod.Full, ValueError, OSError):
                self.dropped += 1

        with self.lock:
            self.total += 1
            self.codes[code] += 1
            self.last_event = (time.monotonic(), code)

            if code == "GPS":
                self.gps = data
            elif code == "ForceCarPassInfo":
                self._merge_radar(data)
            elif "TrafficCar" in data:
                group_id = data.get("GroupID")
                if group_id is None:
                    return
                record = self.passes.get(group_id)
                if record is None:
                    record = VehiclePass(group_id)
                    self.passes[group_id] = record
                record.update(data)

            self._prune()

    def _merge_radar(self, data):
        """ForceCarPassInfo carries a bare speed; attach it to its pass."""
        for entry in data.get("ObjectList") or []:
            object_id = entry.get("ObjectID")
            speed = (entry.get("Extra") or {}).get("Speed")
            for record in reversed(self.passes.values()):
                if record.object_id == object_id:
                    record.radar_speed = speed
                    break

    def _prune(self, keep=120):
        now = time.monotonic()
        stale = [k for k, v in self.passes.items() if now - v.updated > keep]
        for key in stale:
            del self.passes[key]

    def snapshot(self, ttl):
        """Thread-safe read: (boxes to draw, recent passes, status line)."""
        now = time.monotonic()
        with self.lock:
            records = list(self.passes.values())
            status = self.status
            total = self.total
            gps = self.gps
            last = self.last_event
        active = [r for r in records if r.box and now - r.updated < ttl]
        recent = sorted(records, key=lambda r: r.created, reverse=True)[:7]
        age = now - last[0] if last else None
        return active, recent, status, total, gps, age


class FrameGrabber(threading.Thread):
    """Keeps only the newest frame so the view never falls behind the events."""

    def __init__(self, source):
        super().__init__(daemon=True)
        os.environ.setdefault("OPENCV_FFMPEG_CAPTURE_OPTIONS",
                              "rtsp_transport;tcp")
        self.capture = cv2.VideoCapture(source, cv2.CAP_FFMPEG)
        self.capture.set(cv2.CAP_PROP_BUFFERSIZE, 1)
        self.frame = None
        self.running = True
        self.reads = 0

    def opened(self):
        return self.capture.isOpened()

    def run(self):
        while self.running:
            success, frame = self.capture.read()
            if not success:
                time.sleep(0.05)
                continue
            self.frame = frame
            self.reads += 1

    def stop(self):
        self.running = False
        time.sleep(0.1)
        self.capture.release()


def shade(frame, x, y, w, h, alpha=0.74):
    """Darken a rectangle in place so text stays readable over the road."""
    x, y = max(x, 0), max(y, 0)
    roi = frame[y:y + h, x:x + w]
    if roi.size == 0:
        return
    panel = np.full(roi.shape, COL_PANEL, dtype=np.uint8)
    cv2.addWeighted(panel, alpha, roi, 1 - alpha, 0, roi)


def draw_boxes(frame, records, unit):
    height, width = frame.shape[:2]
    for record in records:
        left, top, right, bottom = record.box
        x1 = int(left / NORM * width)
        y1 = int(top / NORM * height)
        x2 = int(right / NORM * width)
        y2 = int(bottom / NORM * height)
        colour = record.colour

        cv2.rectangle(frame, (x1, y1), (x2, y2), colour, max(1, int(2 * unit)))
        # corner ticks, so a thin box still reads at small scales
        tick = int(14 * unit)
        for cx, cy, dx, dy in ((x1, y1, 1, 1), (x2, y1, -1, 1),
                               (x1, y2, 1, -1), (x2, y2, -1, -1)):
            cv2.line(frame, (cx, cy), (cx + dx * tick, cy), colour,
                     max(1, int(3 * unit)))
            cv2.line(frame, (cx, cy), (cx, cy + dy * tick), colour,
                     max(1, int(3 * unit)))

        label = record.speed_label
        if record.plate:
            label += f"  {record.plate}"
        scale = 0.52 * unit
        pad = int(6 * unit)
        (tw, th), _ = cv2.getTextSize(label, FONT, scale, 1)
        bw, bh = tw + pad * 2, th + pad * 2
        # Keep the label inside the frame, above the box unless there is no room.
        lx = min(max(x1, 0), max(0, width - bw))
        ly = y1 - int(6 * unit) - bh
        if ly < 0:
            ly = min(y1 + int(6 * unit), height - bh)
        shade(frame, lx, ly, bw, bh, 0.82)
        cv2.putText(frame, label, (lx + pad, ly + bh - pad), FONT, scale,
                    COL_TEXT, 1, cv2.LINE_AA)

        if record.violations:
            sub = short(record.violations)
            sscale = 0.42 * unit
            (sw, sh), _ = cv2.getTextSize(sub, FONT, sscale, 1)
            bw, bh = sw + pad * 2, sh + pad * 2
            sx = min(max(x1, 0), max(0, width - bw))
            sy = y2 + int(4 * unit)
            if sy + bh > height:                 # slide inside the box instead
                sy = max(0, y2 - bh - int(4 * unit))
            shade(frame, sx, sy, bw, bh, 0.82)
            cv2.putText(frame, sub, (sx + pad, sy + bh - pad), FONT, sscale,
                        COL_VIOLATION, 1, cv2.LINE_AA)


def draw_status(frame, unit, status, total, gps, age, fps, source_size):
    width = frame.shape[1]
    bar = int(30 * unit)
    shade(frame, 0, 0, width, bar, 0.8)

    live = status == "live"
    dot = COL_CLEAN if live else COL_VIOLATION
    cv2.circle(frame, (int(14 * unit), bar // 2), max(2, int(4 * unit)), dot, -1)

    fix = "no fix"
    if gps and gps.get("PositioningResult"):
        fix = "fix"
    elif gps:
        fix = f"no fix ({gps.get('SatelliteCount', 0)} sat)"

    quiet = f"{age:4.1f}s" if age is not None else "  -  "
    left = (f"EVENTS {status.upper()}   {total} received   last {quiet}   "
            f"GPS {fix}")
    right = (f"{source_size[0]}x{source_size[1]} source   "
             f"{frame.shape[1]}x{frame.shape[0]} view   {fps:4.1f} fps")

    scale = 0.46 * unit
    cv2.putText(frame, left, (int(26 * unit), int(20 * unit)), FONT, scale,
                COL_TEXT, 1, cv2.LINE_AA)
    (rw, _), _ = cv2.getTextSize(right, FONT, scale, 1)
    cv2.putText(frame, right, (width - rw - int(14 * unit), int(20 * unit)),
                FONT, scale, COL_DIM, 1, cv2.LINE_AA)


def draw_speeds(frame, record, unit, top):
    """Every speed field for the newest pass, radar provenance called out.

    Sits in the right-hand column under the pass list: the road itself runs
    through the middle and left, and a panel there clips the box labels.
    """
    if record is None:
        return
    height, width = frame.shape[:2]
    pw = int(300 * unit)
    row = int(19 * unit)
    ph = int(46 * unit) + row * len(SPEED_FIELDS)
    px = width - pw - int(12 * unit)
    py = min(top + int(10 * unit), max(0, height - ph - int(12 * unit)))

    shade(frame, px, py, pw, ph, 0.80)
    cv2.putText(frame, "SPEED FIELDS", (px + int(12 * unit),
                py + int(20 * unit)), FONT, 0.42 * unit, COL_ACCENT, 1,
                cv2.LINE_AA)
    verdict = "RADAR" if record.measured else "NO RADAR SOURCE"
    vcol = COL_CLEAN if record.measured else COL_VIOLATION
    (vw, _), _ = cv2.getTextSize(verdict, FONT, 0.38 * unit, 1)
    cv2.putText(frame, verdict, (px + pw - vw - int(12 * unit),
                py + int(20 * unit)), FONT, 0.38 * unit, vcol, 1, cv2.LINE_AA)

    y = py + int(38 * unit)
    for name, _ in SPEED_FIELDS:
        value = record.speed_fields.get(name)
        radar = name in RADAR_FIELDS
        shown = "-" if value is None else str(value)

        if radar:
            # Mark the provenance fields hard: they are the whole question.
            live = value not in (None, 0, 0.0)
            colour = COL_CLEAN if live else COL_VIOLATION
            shade(frame, px + int(6 * unit), y - int(13 * unit),
                  pw - int(12 * unit), row - int(2 * unit), 0.5)
            cv2.rectangle(frame, (px + int(6 * unit), y - int(13 * unit)),
                          (px + pw - int(6 * unit), y + row - int(15 * unit)),
                          colour, 1)
            cv2.putText(frame, "*", (px + int(10 * unit), y), FONT,
                        0.40 * unit, colour, 1, cv2.LINE_AA)
            label, lcol = name, colour
        elif value is None or value in PLACEHOLDER_SPEEDS:
            label, lcol, colour = name, COL_DIM, COL_DIM
        else:
            label, lcol, colour = name, COL_TEXT, COL_ACCENT

        cv2.putText(frame, label, (px + int(20 * unit), y), FONT,
                    0.36 * unit, lcol, 1, cv2.LINE_AA)
        (sw, _), _ = cv2.getTextSize(shown, FONT, 0.38 * unit, 1)
        cv2.putText(frame, shown, (px + pw - sw - int(14 * unit), y), FONT,
                    0.38 * unit, colour, 1, cv2.LINE_AA)
        y += row


def draw_recent(frame, records, unit):
    """Returns the y coordinate the panel ends at, for stacking below it."""
    if not records:
        return int(42 * unit)
    height, width = frame.shape[:2]
    pw = int(300 * unit)
    row = int(42 * unit)
    ph = int(34 * unit) + row * len(records)
    px = width - pw - int(12 * unit)
    py = int(42 * unit)

    shade(frame, px, py, pw, ph, 0.78)
    cv2.putText(frame, "RECENT PASSES", (px + int(12 * unit),
                py + int(22 * unit)), FONT, 0.42 * unit, COL_ACCENT, 1,
                cv2.LINE_AA)

    y = py + int(34 * unit)
    for record in records:
        cv2.line(frame, (px, y), (px + pw, y), (54, 48, 42), 1)
        if record.measured:
            speed = f"{record.speed}" if record.speed is not None else "--"
            colour = COL_VIOLATION if record.over_limit else COL_TEXT
            cv2.putText(frame, speed, (px + int(12 * unit), y + int(21 * unit)),
                        FONT, 0.62 * unit, colour, 1, cv2.LINE_AA)
            cv2.putText(frame, "km/h", (px + int(56 * unit), y + int(21 * unit)),
                        FONT, 0.36 * unit, COL_DIM, 1, cv2.LINE_AA)
        else:
            cv2.putText(frame, "n/a", (px + int(12 * unit), y + int(21 * unit)),
                        FONT, 0.52 * unit, COL_DIM, 1, cv2.LINE_AA)

        head = record.plate or (record.category or "unknown")
        cv2.putText(frame, head[:16], (px + int(96 * unit),
                    y + int(17 * unit)), FONT, 0.42 * unit, COL_TEXT, 1,
                    cv2.LINE_AA)

        note = short(record.violations) if record.violations else "clean"
        note_col = COL_VIOLATION if record.violations else COL_CLEAN
        cv2.putText(frame, note, (px + int(96 * unit),
                    y + int(32 * unit)), FONT, 0.34 * unit, note_col, 1,
                    cv2.LINE_AA)

        cv2.putText(frame, record.clock, (px + pw - int(58 * unit),
                    y + int(32 * unit)), FONT, 0.32 * unit, COL_DIM, 1,
                    cv2.LINE_AA)
        y += row
    return py + ph


def build_parser():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--host", default=os.environ.get("RADAR_HOST", CAMERA_IP))
    parser.add_argument("--user", default=os.environ.get("RADAR_USER", "admin"))
    parser.add_argument("--password", default=os.environ.get("RADAR_PASSWORD",
                                                             "admin123"))
    size = parser.add_mutually_exclusive_group()
    size.add_argument("--width", type=int, default=1280,
                      help="display width in pixels (default: 1280)")
    size.add_argument("--scale", type=float,
                      help="scale factor applied to the 4096x2160 source")
    parser.add_argument("--ttl", type=float, default=4.0,
                        help="seconds to keep a box on screen (default: 4)")
    parser.add_argument("--rtsp", default=None,
                        help="override the RTSP URL")
    parser.add_argument("--no-viewer", action="store_true",
                        help="skip the JSON reader window")
    return parser


def main():
    args = build_parser().parse_args()
    rtsp = args.rtsp or (f"rtsp://{args.user}:{args.password}@{args.host}"
                         ":554/live")

    # Tk and OpenCV each want their own main thread, so the reader is its own
    # process and gets events over a queue.
    sink, viewer = None, None
    if not args.no_viewer:
        sink = mp.Queue(maxsize=2000)
        viewer = mp.Process(target=run_viewer, args=(sink,), daemon=True)
        viewer.start()

    events = EventStream(args.host, args.user, args.password, sink=sink)
    events.start()

    print(f"connecting to {args.host} ...")
    grabber = FrameGrabber(rtsp)
    if not grabber.opened():
        print("could not open the RTSP stream; check the host and credentials")
        return
    grabber.start()

    source_w = int(grabber.capture.get(cv2.CAP_PROP_FRAME_WIDTH)) or 4096
    source_h = int(grabber.capture.get(cv2.CAP_PROP_FRAME_HEIGHT)) or 2160
    scale = args.scale if args.scale else args.width / source_w

    window = "radar"
    cv2.namedWindow(window, cv2.WINDOW_NORMAL)
    cv2.resizeWindow(window, int(source_w * scale), int(source_h * scale))

    show_boxes = True
    show_panel = True
    show_speeds = True
    times = collections.deque(maxlen=30)
    print("running - q quits, +/- resizes, b boxes, h panel, s saves a frame")

    try:
        while True:
            frame = grabber.frame
            if frame is None:
                if cv2.waitKey(30) & 0xFF in (ord("q"), 27):
                    break
                continue

            view = cv2.resize(frame, (max(320, int(source_w * scale)),
                                      max(180, int(source_h * scale))),
                              interpolation=cv2.INTER_AREA)
            unit = view.shape[1] / 1280.0  # keep text legible at any scale

            active, recent, status, total, gps, age = events.snapshot(args.ttl)
            if show_boxes:
                draw_boxes(view, active, unit)

            times.append(time.monotonic())
            fps = 0.0
            if len(times) > 1:
                span = times[-1] - times[0]
                fps = (len(times) - 1) / span if span else 0.0

            if show_panel:
                draw_status(view, unit, status, total, gps, age, fps,
                            (source_w, source_h))
                bottom = draw_recent(view, recent, unit)
                if show_speeds:
                    draw_speeds(view, recent[0] if recent else None, unit,
                                bottom)

            cv2.imshow(window, view)

            key = cv2.waitKey(1) & 0xFF
            if key in (ord("q"), 27):
                break
            if key in (ord("+"), ord("=")):
                scale = min(scale * 1.15, 1.0)
                cv2.resizeWindow(window, int(source_w * scale),
                                 int(source_h * scale))
            elif key in (ord("-"), ord("_")):
                scale = max(scale / 1.15, 0.08)
                cv2.resizeWindow(window, int(source_w * scale),
                                 int(source_h * scale))
            elif key == ord("b"):
                show_boxes = not show_boxes
            elif key == ord("h"):
                show_panel = not show_panel
            elif key == ord("f"):
                show_speeds = not show_speeds
            elif key == ord("s"):
                name = time.strftime("frame-%Y%m%d-%H%M%S.png")
                cv2.imwrite(name, view)
                print(f"saved {name}")
    finally:
        events.running = False
        grabber.stop()
        cv2.destroyAllWindows()
        if viewer is not None and viewer.is_alive():
            viewer.terminate()
            viewer.join(timeout=2)


if __name__ == "__main__":
    mp.freeze_support()
    main()

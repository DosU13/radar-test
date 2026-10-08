"""A readable JSON reader for the camera's event stream.

Runs as a second window beside radar_view.py, or on its own against a capture:

    python json_viewer.py events.jsonl

A traffic event carries ~113 field paths, a quarter of which are nulls, empty
strings, zeroed boxes and "unknow" placeholders. "Hide empty" is on by default
and drops those, which is the difference between scrolling a payload and
reading one. Toggle it off to see the raw shape.
"""
import collections
import json
import queue as queue_mod
import sys
import tkinter as tk
from tkinter import ttk

BG = "#16181C"
BG_ALT = "#1D2026"
BG_PANEL = "#111317"
FG = "#E3E6EA"
FG_DIM = "#8C939D"
ACCENT = "#EFA23F"
STRING = "#9AD1B0"
NUMBER = "#7FC4DC"
VIOLATION = "#FF7365"
LINE = "#2B3038"

MONO = ("Consolas", 10)
MONO_SMALL = ("Consolas", 9)
UI = ("Segoe UI", 9)

MAX_EVENTS = 800
MISSING = object()

# Values the device sends when a feature is wired but idle.
STUB_STRINGS = {"", "unknow", "unknown "}

# Empty here is the answer, not noise: a blank ViolationDesc is how the camera
# says "the rule ran and nothing was violated". Never hide these.
ALWAYS_SHOW = {"ViolationDesc", "ViolationCode"}


def prune(value):
    """Drop nulls, blanks, empty containers and all-zero arrays."""
    if isinstance(value, dict):
        kept = {}
        for key, item in value.items():
            cleaned = prune(item)
            if cleaned is MISSING and key in ALWAYS_SHOW:
                cleaned = item
            if cleaned is not MISSING:
                kept[key] = cleaned
        return kept or MISSING
    if isinstance(value, list):
        if not value:
            return MISSING
        if any(isinstance(item, (dict, list)) for item in value):
            kept = [c for c in (prune(i) for i in value) if c is not MISSING]
            return kept or MISSING
        if all(item in (0, "", None) for item in value):
            return MISSING
        return value
    if value is None:
        return MISSING
    if isinstance(value, str) and value in STUB_STRINGS:
        return MISSING
    return value


def values_of(obj):
    """Every leaf value, for the filter box.

    Searching the raw JSON dump would match field names too, so "overspeed"
    would hit every event carrying an OverSpeedMargin field. Values only.
    """
    found = []
    stack = [obj]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            stack.extend(item.values())
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, bool) or item is None:
            continue
        elif isinstance(item, (str, int, float)) and item != "":
            found.append(str(item))
    return found


def summarize(event):
    """One line describing an event, using the fields that actually vary."""
    data = event.get("data") or {}
    code = event.get("code", "?")

    if code == "GPS":
        fixed = data.get("PositioningResult")
        sats = data.get("SatelliteCount", 0)
        return "fix" if fixed else f"no fix, {sats} sat"

    if code == "ForceCarPassInfo":
        for entry in data.get("ObjectList") or []:
            extra = entry.get("Extra") or {}
            return (f"{extra.get('Speed', '?')} km/h "
                    f"{extra.get('DrivingDirection', '')}").strip()
        return ""

    car = data.get("TrafficCar") or {}
    bits = []
    # Top-level Speed is the live measurement; TrafficCar.Speed lags it.
    speed = next((v for v in (data.get("Speed"), car.get("Speed"))
                  if v is not None), None)
    if speed is not None:
        bits.append(f"{speed} km/h")
    plate = (data.get("Object") or {}).get("Text")
    if plate:
        bits.append(plate)
    elif (data.get("Vehicle") or {}).get("Category"):
        bits.append(data["Vehicle"]["Category"])
    if car.get("ViolationDesc"):
        bits.append(car["ViolationDesc"])
    return "  ".join(bits)


def preview(value):
    """Short right-hand-column text for one node."""
    if isinstance(value, dict):
        return f"{{{len(value)}}}"
    if isinstance(value, list):
        if all(not isinstance(i, (dict, list)) for i in value):
            body = ", ".join(json.dumps(i) for i in value)
            return f"[{body}]" if len(body) <= 48 else f"[{len(value)} items]"
        return f"[{len(value)}]"
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, str):
        return f'"{value}"'
    return str(value)


def tag_for(value):
    if isinstance(value, str):
        return "string"
    if isinstance(value, bool) or value is None:
        return "special"
    if isinstance(value, (int, float)):
        return "number"
    return "branch"


class Viewer:
    def __init__(self, root, source=None, events=()):
        self.root = root
        self.source = source
        self.events = collections.deque(maxlen=MAX_EVENTS)
        self.rows = {}
        self.seq = 0
        self.total = 0
        self.dropped = 0

        root.title("radar - event JSON")
        root.geometry("1260x760")
        root.configure(bg=BG)
        self._style()
        self._build()

        for event in events:
            self.add(event)
        self.rebuild()

        if source is not None:
            root.after(150, self.pump)

    # ---------------------------------------------------------------- chrome

    def _style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", background=BG, foreground=FG, font=UI)
        style.configure("TFrame", background=BG)
        style.configure("TLabel", background=BG, foreground=FG_DIM)
        style.configure("TCheckbutton", background=BG, foreground=FG_DIM,
                        indicatorbackground=BG_ALT, indicatorforeground=ACCENT,
                        focuscolor=BG)
        style.map("TCheckbutton", background=[("active", BG)],
                  foreground=[("active", FG)],
                  indicatorbackground=[("selected", ACCENT),
                                       ("active", LINE)])
        style.configure("TButton", background=BG_ALT, foreground=FG,
                        borderwidth=0, padding=(10, 4))
        style.map("TButton", background=[("active", LINE)])
        style.configure("TEntry", fieldbackground=BG_ALT, foreground=FG,
                        insertcolor=FG, borderwidth=0, padding=4)
        style.map("TEntry", fieldbackground=[("!disabled", BG_ALT)],
                  foreground=[("!disabled", FG)])
        style.configure("TCombobox", fieldbackground=BG_ALT, background=BG_ALT,
                        foreground=FG, arrowcolor=FG_DIM, borderwidth=0,
                        padding=4)
        # A readonly combobox draws from the readonly/selected states, so
        # without these the chosen value renders invisible on the dark field.
        style.map("TCombobox",
                  fieldbackground=[("readonly", BG_ALT), ("!disabled", BG_ALT)],
                  foreground=[("readonly", FG), ("!disabled", FG)],
                  selectbackground=[("readonly", BG_ALT)],
                  selectforeground=[("readonly", FG)],
                  background=[("readonly", BG_ALT)])
        style.configure("Vertical.TScrollbar", background=BG_ALT,
                        troughcolor=BG, bordercolor=BG, arrowcolor=FG_DIM,
                        darkcolor=BG_ALT, lightcolor=BG_ALT, borderwidth=0)
        style.map("Vertical.TScrollbar", background=[("active", LINE)])
        style.configure("Treeview", background=BG_PANEL,
                        fieldbackground=BG_PANEL, foreground=FG,
                        borderwidth=0, rowheight=21, font=MONO_SMALL)
        style.configure("Treeview.Heading", background=BG_ALT,
                        foreground=FG_DIM, borderwidth=0, font=UI)
        style.map("Treeview.Heading", background=[("active", LINE)])
        style.map("Treeview", background=[("selected", "#3A2E1C")],
                  foreground=[("selected", ACCENT)])
        style.configure("TPanedwindow", background=BG)
        style.configure("TNotebook", background=BG, borderwidth=0)
        style.configure("TNotebook.Tab", background=BG, foreground=FG_DIM,
                        padding=(14, 5), borderwidth=0)
        style.map("TNotebook.Tab", background=[("selected", BG_ALT)],
                  foreground=[("selected", ACCENT)])

    def _build(self):
        bar = ttk.Frame(self.root, padding=(10, 8))
        bar.pack(fill="x")

        ttk.Label(bar, text="Filter").pack(side="left", padx=(0, 6))
        self.filter_var = tk.StringVar()
        self.filter_var.trace_add("write", lambda *_: self.rebuild())
        entry = ttk.Entry(bar, textvariable=self.filter_var, width=26)
        entry.pack(side="left")
        entry.bind("<Escape>", lambda _: self.filter_var.set(""))

        ttk.Label(bar, text="Code").pack(side="left", padx=(14, 6))
        self.code_var = tk.StringVar(value="all")
        self.code_box = ttk.Combobox(bar, textvariable=self.code_var,
                                     values=["all"], width=26,
                                     state="readonly")
        self.code_box.pack(side="left")
        self.code_box.bind("<<ComboboxSelected>>", lambda _: self.rebuild())

        self.hide_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Hide empty", variable=self.hide_var,
                        command=self.reshow).pack(side="left", padx=(16, 0))
        self.follow_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(bar, text="Follow newest",
                        variable=self.follow_var).pack(side="left", padx=(10, 0))

        ttk.Button(bar, text="Expand", command=lambda: self.expand(True)
                   ).pack(side="right")
        ttk.Button(bar, text="Collapse", command=lambda: self.expand(False)
                   ).pack(side="right", padx=(0, 6))
        ttk.Button(bar, text="Clear", command=self.clear
                   ).pack(side="right", padx=(0, 6))

        split = ttk.PanedWindow(self.root, orient="horizontal")
        split.pack(fill="both", expand=True, padx=10)

        left = ttk.Frame(split)
        self.list = ttk.Treeview(left, columns=("time", "code", "detail"),
                                 show="headings", selectmode="browse")
        # "TrafficNonMotorWithoutSafehat" is 29 characters; anything narrower
        # clips the one column you scan by.
        for name, title, width, low in (("time", "time", 70, 62),
                                        ("code", "code", 222, 180),
                                        ("detail", "detail", 250, 140)):
            self.list.heading(name, text=title)
            self.list.column(name, width=width, minwidth=low,
                             stretch=(name == "detail"), anchor="w")
        self.list.tag_configure("violation", foreground=VIOLATION)
        self.list.tag_configure("plain", foreground=FG)
        bar_l = ttk.Scrollbar(left, orient="vertical", command=self.list.yview)
        self.list.configure(yscrollcommand=bar_l.set)
        self.list.pack(side="left", fill="both", expand=True)
        bar_l.pack(side="right", fill="y")
        self.list.bind("<<TreeviewSelect>>", self.on_select)
        split.add(left, weight=3)

        right = ttk.Notebook(split)

        tree_tab = ttk.Frame(right)
        self.tree = ttk.Treeview(tree_tab, columns=("value",), selectmode="browse")
        self.tree.heading("#0", text="field")
        self.tree.heading("value", text="value")
        self.tree.column("#0", width=250, stretch=False)
        self.tree.column("value", width=330, stretch=True)
        self.tree.tag_configure("string", foreground=STRING)
        self.tree.tag_configure("number", foreground=NUMBER)
        self.tree.tag_configure("special", foreground=FG_DIM)
        self.tree.tag_configure("branch", foreground=ACCENT)
        self.tree.tag_configure("flag", foreground=VIOLATION)
        bar_r = ttk.Scrollbar(tree_tab, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=bar_r.set)
        self.tree.pack(side="left", fill="both", expand=True)
        bar_r.pack(side="right", fill="y")
        right.add(tree_tab, text="Tree")

        raw_tab = ttk.Frame(right)
        self.raw = tk.Text(raw_tab, bg=BG_PANEL, fg=FG, font=MONO,
                           insertbackground=FG, borderwidth=0, wrap="none",
                           padx=10, pady=8)
        bar_raw = ttk.Scrollbar(raw_tab, orient="vertical", command=self.raw.yview)
        self.raw.configure(yscrollcommand=bar_raw.set)
        self.raw.pack(side="left", fill="both", expand=True)
        bar_raw.pack(side="right", fill="y")
        right.add(raw_tab, text="Raw")
        split.add(right, weight=4)
        # Give the event list its full column width on first paint.
        self.root.after(60, lambda: split.sashpos(0, 560))

        self.status = ttk.Label(self.root, text="waiting for events",
                                anchor="w", padding=(12, 6))
        self.status.pack(fill="x")

        self.root.bind("<Control-f>", lambda _: entry.focus_set())
        self.root.bind("<Control-l>", lambda _: self.clear())

    # ------------------------------------------------------------------ data

    def pump(self):
        """Drain whatever the capture process has sent since the last tick."""
        arrived = False
        for _ in range(400):
            try:
                event = self.source.get_nowait()
            except queue_mod.Empty:
                break
            except (OSError, EOFError):
                self.status.configure(text="capture process closed the stream")
                return
            if event is None:
                continue
            self.add(event)
            arrived = True
        if arrived:
            self.rebuild()
        self.root.after(150, self.pump)

    def add(self, event):
        self.seq += 1
        self.total += 1
        event["_id"] = str(self.seq)
        event["_summary"] = summarize(event)
        event["_haystack"] = " ".join(
            [event.get("code", ""), event["_summary"]]
            + values_of(event.get("data") or {})).lower()
        self.events.append(event)

        codes = sorted({e.get("code", "?") for e in self.events})
        if list(self.code_box["values"])[1:] != codes:
            self.code_box["values"] = ["all"] + codes

    def visible(self):
        needle = self.filter_var.get().strip().lower()
        code = self.code_var.get()
        out = []
        for event in self.events:
            if code != "all" and event.get("code") != code:
                continue
            if needle and needle not in event["_haystack"]:
                continue
            out.append(event)
        return out

    def rebuild(self):
        selected = self.list.selection()
        keep = selected[0] if selected else None

        self.list.delete(*self.list.get_children())
        self.rows.clear()
        shown = self.visible()
        for event in reversed(shown):            # newest first
            car = (event.get("data") or {}).get("TrafficCar") or {}
            tag = "violation" if car.get("ViolationDesc") else "plain"
            self.list.insert("", "end", iid=event["_id"], tags=(tag,),
                             values=(event.get("time", "")[-8:],
                                     event.get("code", "?"),
                                     event["_summary"]))
            self.rows[event["_id"]] = event

        if self.follow_var.get() and shown:
            newest = shown[-1]["_id"]
            self.list.selection_set(newest)
            self.list.see(newest)
        elif keep and keep in self.rows:
            self.list.selection_set(keep)

        self.status.configure(
            text=f"{self.total} received   {len(shown)} shown   "
                 f"{len(self.events)} buffered"
            + (f"   {self.dropped} dropped" if self.dropped else ""))

    def on_select(self, _event=None):
        selection = self.list.selection()
        if not selection:
            return
        event = self.rows.get(selection[0])
        if event:
            self.show(event)

    def reshow(self):
        selection = self.list.selection()
        if selection and selection[0] in self.rows:
            self.show(self.rows[selection[0]])

    def show(self, event):
        data = event.get("data") or {}
        if self.hide_var.get():
            cleaned = prune(data)
            data = {} if cleaned is MISSING else cleaned

        self.tree.delete(*self.tree.get_children())
        header = self.tree.insert("", "end", text=event.get("code", "?"),
                                  values=(f"{event.get('action', '')} "
                                          f"@ {event.get('time', '')}",),
                                  open=True, tags=("branch",))
        self.insert(header, data)
        for child in self.tree.get_children(header):
            self.tree.item(child, open=True)

        self.raw.delete("1.0", "end")
        self.raw.insert("1.0", json.dumps(data, indent=2, ensure_ascii=False))

    def insert(self, parent, value):
        if isinstance(value, dict):
            for key, item in value.items():
                tag = tag_for(item)
                if key in ("ViolationDesc", "ViolationCode") and item:
                    tag = "flag"
                node = self.tree.insert(parent, "end", text=key,
                                        values=(preview(item),), tags=(tag,))
                if isinstance(item, (dict, list)):
                    self.insert(node, item)
        elif isinstance(value, list):
            for index, item in enumerate(value):
                if not isinstance(item, (dict, list)):
                    continue
                node = self.tree.insert(parent, "end", text=f"[{index}]",
                                        values=(preview(item),),
                                        tags=("branch",))
                self.insert(node, item)

    def expand(self, opened):
        def walk(node):
            for child in self.tree.get_children(node):
                self.tree.item(child, open=opened)
                walk(child)
        walk("")

    def clear(self):
        self.events.clear()
        self.rows.clear()
        self.tree.delete(*self.tree.get_children())
        self.raw.delete("1.0", "end")
        self.rebuild()


def run_viewer(source=None, events=()):
    """Entry point for the child process (and for standalone use)."""
    root = tk.Tk()
    Viewer(root, source=source, events=events)
    try:
        root.mainloop()
    except KeyboardInterrupt:
        pass


def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "events.jsonl"
    try:
        with open(path, encoding="utf-8") as handle:
            events = [json.loads(line) for line in handle if line.strip()]
    except FileNotFoundError:
        print(f"no such capture: {path}")
        print("run live-info.py first, or pass a path to a .jsonl capture")
        return
    print(f"loaded {len(events)} events from {path}")
    run_viewer(events=events[-MAX_EVENTS:])


if __name__ == "__main__":
    main()

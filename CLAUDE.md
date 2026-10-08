# RadarTest — Dahua ITC952 traffic camera

Reverse-engineering a Dahua ITC952-RF2D-IR traffic enforcement camera: reading its
event stream, overlaying it on the video, and working out why its radar never
reports a speed.

## The headline finding — read this first

**The speeds this camera reports are fabricated.** When no real measurement
arrives, the firmware invents a value inside the configured speed limit. This is
documented behaviour: manual **§6.5.1.4.1, Table 6-11**, the *Pre Speed Wait /
Delay Speed Wait* row (printed pages 47–48) — the sentence is split across the
page break, which is why it is easy to miss.

Proven by experiment, not inference:

| Configured `SmallCarSpeedLimit` | Speeds reported |
|---|---|
| `[10, 70]` | 21, 23, 27, 35, 37, 38, 42, 48, 50, 52, 55, 58, 60 |
| `[80, 95]` | 81, 82, 84, 85, 90, 90, 91, 91, 91, 91, 92, 92 |
| `[1, 250]` | up to 248 km/h |

Change one config field and every car on the road instantly "drives" at a
different speed. **Never trust a speed value from this camera.**

### The only proof a speed is real

`RadarSpeedSourceTime` and `RadarSpeedSetTime` in the event payload. The camera
stamps these when a radar sample actually lands. An invented speed never carries
them.

**They have been `0.0` in every event ever captured from this camera** — before
any config change, after every change, radar enabled and disabled, every
protocol, baud, work mode, detect mode, sensitivity, wait window and speed range
we tried. Zero radar samples, ever.

## Device

| | |
|---|---|
| Model | ITC952-RF2D-IR, serial `5M0175APAJ7FC30` |
| Firmware | `2.622.0000000.7.R`, build 2019-03-21 |
| SoC | HiSilicon HI3519_V101 |
| Work camera | `172.17.83.60`, `admin` / `admin123` |
| Video | 4096×2160 @ 13 fps, `rtsp://admin:admin123@172.17.83.60:554/live` |
| Business mode | GV (ANPR) |
| Radar | **external unit**, 3-channel port `R1/T1/G`…`R3/T3/G`, or RS-485 `A1/B1` |
| Supported radar protocols | `ITARD-024SA-I`, `ITARD-024SA-ST`, `ITARD-024MA-H` (RS-485) only |

**Working:** plate recognition, vehicle classification, seat-belt and phone
detection, bounding boxes.
**Not working:** speed. No radar has ever delivered a sample.

## Current task — on-site visit

Visiting another camera that reportedly has a working radar, to (a) confirm it
actually works and (b) bring back a **known-good config** to diff against ours.

Blocked on: the camera is connected directly by Ethernet to a laptop and its IP
is unknown. Known MAC: `BC:32:5F:D7:2F:07` (`BC:32:5F` = Zhejiang Dahua).

A direct cable means no DHCP, so the laptop sits on `169.254.x.x` while the
camera keeps a static IP. Different subnets — **no IP packet can pass**, which is
why ping, port scans and ONVIF all find nothing. ARP is below IP and ignores
subnets, so ARP capture is the reliable way in.

```bash
python arp_find.py --seconds 60          # ADMIN PowerShell. Best option.
python find_camera.py                    # discovery + likely addresses
python find_camera.py --sweep 192.168 --mac BC:32:5F:D7:2F:07
python whatis.py <IP>                    # what is this device? no creds needed
python radar_check.py <IP> --seconds 300 # the actual diagnosis
python radar_check.py --compare good.txt bad.txt
```

Sweeping only reaches addresses the laptop thinks are on-link. Give the adapter
a /16 first, in an admin prompt:

```
netsh interface ip add address "Ethernet" 192.168.99.50 255.255.0.0
netsh interface ip delete address "Ethernet" 192.168.99.50
```

## Files

| File | Purpose |
|---|---|
| `radar_view.py` | Main app: RTSP video + live event overlay, boxes, speed-field panel |
| `json_viewer.py` | Tkinter JSON reader, runs as a second process beside radar_view |
| `radar_check.py` | Field tool: is the radar delivering data? Saves config + events |
| `find_camera.py` | Locate a camera on a direct link (discovery / ONVIF / sweep) |
| `arp_find.py` | Find a camera by capturing its ARP (pktmon, Windows, admin) |
| `whatis.py` | Identify a device at an IP without credentials |
| `live-info.py` | Original simple event-stream capture to `events.jsonl` |
| `capture.py` | Original bare RTSP viewer |
| `config_all.txt` | Full config dump taken **before** any changes — the baseline |

Only `radar_view.py` / `json_viewer.py` need `opencv-python`, `numpy`,
`requests`. The field tools need `requests` or nothing at all.

## Event stream — hard-won details

Endpoint: `http://<ip>/cgi-bin/eventManager.cgi?action=attach&codes=[All]`,
HTTP Digest auth, `multipart/x-mixed-replace`, boundary `--myboundary`.
All parts are `text/plain` — **no images cross this stream**.

- **`iter_content(chunk_size=None)` hangs forever.** urllib3 reads to EOF and
  this response never ends. Use `chunk_size=1` and scan for the boundary in
  bytes (also avoids splitting multi-byte characters).
- **The JSON is pretty-printed across ~150 lines.** Line-by-line reading only
  ever catches fragments; buffer to the next boundary.
- **One vehicle pass = a burst of ~10 events** sharing a `GroupID`, each
  repeating the whole record. Key on `GroupID` to get one row per car.
  `IndexInGroup`/`CountInGroup` is *not* a reliable dedupe key.
- **Read the top-level `Speed`, not `TrafficCar.Speed`.** The top-level field is
  the live measurement; `TrafficCar.Speed` holds the first value it saw, and the
  violation events in a burst carry only a placeholder (`5` or `0`). Letting the
  last event win gives you `5` forever. This bug cost days.
- **The plate is in `Object.Text`**, never `Vehicle.Plate.Text` (always empty).
  Only present when `Object.ObjectType == "Plate"`.
- **Bounding boxes are in a fixed 0–8191 space**, not pixels. Map with
  `x * width / 8192`.
- `ViolationDesc` is authoritative, not the event `Code` — an empty
  `ViolationDesc` means the rule ran and nothing was violated.
- `Extension.EventLongID` is the best primary key (device prefix + timestamp +
  counter).
- `threading.Thread` already has a `_handle` attribute on Python 3.13 — don't
  name a method that.

## Config API

Read and write over the same Digest auth:

```
GET /cgi-bin/configManager.cgi?action=getConfig&name=Radar
GET /cgi-bin/configManager.cgi?action=getConfig&name=All        # ~2 MB
GET /cgi-bin/configManager.cgi?action=setConfig&Radar[0].Enable=true
GET /cgi-bin/magicBox.cgi?action=getSystemInfo
```

URL-encode the brackets (`%5B` / `%5D`). Returns `OK`.

- **`setConfig` does no validation.** It accepted `TriggerMode=4` and
  `SpeedType=3`, both meaningless. "The write stuck" proves nothing.
- The web UI caps some fields (MaxSpeed at 100) but **the API does not** — it
  took 300.
- `Detector[n].SpeedType` and `TriggerMode` are `0` and have never changed,
  including when set directly. Setting them changed no behaviour.
- The UI silently discards edits if you navigate away without pressing OK.

## What is proven vs still unknown

**Proven:** speeds are generated within the configured limit; settings take
effect live (no reboot needed); no radar sample has ever been stamped; the
camera only speaks the three ITARD protocols.

**Unknown:** whether a radar head is physically connected at all, what model it
is, whether it is powered, and whether the wiring/baud is right. None of this is
determinable over the network — hence the site visit.

**Do not repeat:** tuning ranges, protocols, work modes, wait windows or
sensitivity. All were swept exhaustively with the widest possible acceptance
window (limits `[1,250]`, waits 10000 ms, sensitivity 6, both protocols) and
produced zero samples. The bottleneck is hardware, not configuration.

## Reference

- [Manual PDF](https://files.dahua.support/Instrukcje%20obs%C5%82ugi/Angielskie/ITC352&952_Dahua%20HD%20Intelligent%20Traffic%20Camera%20User's%20Manual_V1.0.1.pdf)
  — ITC352 & 952, 124 pages. Radar §6.5.1.4.1 p.47–48; RS485 §6.5.1.4.2 p.48;
  Trigger Mode §6.2.4 p.28; Lane Property §6.5.1.2 p.43–44; Snapshot §6.5.1.3
  p.45–46; Speed Measuring §6.5.1.4.5 p.51–52; port pinout p.5.
- [Field test kit](https://claude.ai/artifact/7vEXXFD21LrTU4pmhC78jQ) — on-site checklist
- [Findings report](https://claude.ai/artifact/FhgdYVSATy4c3jd8jM9DQm) — earlier radar audit (partly superseded)
- [Event stream schema](https://claude.ai/code/artifact/89999107-2bf2-4813-9580-e05af61c3516)

## Working notes

- Config changes are the user's call — ask before writing to the device.
- `config_all.txt` is the pre-change baseline; every original value is in it.
- The radar is an *external* Doppler head. It reports speed only — no position,
  no lane. Lane identity comes from **which COM port the cable is in**
  (COM1→Lane1). One head serves one lane; three lanes need three heads.

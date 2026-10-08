"""Identify the device at an IP - no credentials needed.

    python whatis.py 192.168.1.108

A camera serves its own web UI and holds its own credentials, so a different
UI or a different login means a different device, not a different computer.
This works out what you are actually talking to.

The useful trick: an HTTP 401 challenge carries a `WWW-Authenticate` header,
and Dahua puts the device name in the realm. You learn what it is from the
refusal itself, without ever logging in.
"""
import argparse
import re
import socket
import subprocess
import sys
import urllib.error
import urllib.request

RULE = "-" * 68

PROBES = [
    ("/", "root page"),
    ("/cgi-bin/magicBox.cgi?action=getDeviceType", "Dahua device type"),
    ("/cgi-bin/magicBox.cgi?action=getSystemInfo", "Dahua system info"),
    ("/onvif/device_service", "ONVIF"),
    ("/ISAPI/System/deviceInfo", "Hikvision ISAPI"),
    ("/axis-cgi/param.cgi?action=list", "Axis"),
]


def fetch(url, timeout=5):
    """Return (status, headers, body-prefix). A 401 is a useful answer."""
    request = urllib.request.Request(url, headers={"User-Agent": "whatis/1.0"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read(2000).decode("utf-8", errors="replace")
            return response.status, dict(response.headers), body
    except urllib.error.HTTPError as exc:
        body = ""
        try:
            body = exc.read(2000).decode("utf-8", errors="replace")
        except Exception:
            pass
        return exc.code, dict(exc.headers), body
    except Exception as exc:
        return None, {}, f"{type(exc).__name__}: {exc}"


def port_open(ip, port, timeout=1.2):
    try:
        with socket.create_connection((ip, port), timeout=timeout):
            return True
    except OSError:
        return False


def mac_of(ip):
    try:
        subprocess.run(["ping", "-n", "1", "-w", "800", ip]
                       if sys.platform == "win32" else
                       ["ping", "-c", "1", "-W", "1", ip],
                       capture_output=True, timeout=8)
        cmd = ["arp", "-a", ip] if sys.platform == "win32" else ["arp", "-n", ip]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=8).stdout
        m = re.search(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}", out)
        return m.group(0) if m else None
    except Exception:
        return None


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("ip")
    parser.add_argument("--port", type=int, default=80)
    args = parser.parse_args()
    base = f"http://{args.ip}:{args.port}"

    print(f"\n{RULE}\nIDENTIFYING {args.ip}\n{RULE}")

    mac = mac_of(args.ip)
    if mac:
        print(f"  MAC            {mac}")
        print(f"  OUI            {mac[:8].upper()}  <- look this up to confirm the vendor")
    else:
        print("  MAC            not in the ARP table (different subnet, or no reply)")

    print("\n  open ports:")
    ports = set()
    for port, what in ((80, "http"), (443, "https"), (554, "rtsp"),
                       (37777, "Dahua SDK"), (37810, "Dahua discovery"),
                       (8000, "Hikvision SDK"), (22, "ssh"), (23, "telnet")):
        if port_open(args.ip, port):
            print(f"    {port:6} open   {what}")
            ports.add(port)

    print(f"\n{RULE}\nHTTP PROBES\n{RULE}")
    verdicts = []
    dahua_cgi = False
    for path, label in PROBES:
        status, headers, body = fetch(base + path)
        # 401 on the Dahua CGI means the endpoint EXISTS and wants auth.
        # 404 means it isn't there. That distinction is the real test.
        if path.startswith("/cgi-bin/magicBox") and status in (200, 401):
            dahua_cgi = True
        if status is None:
            print(f"  {label:22} -- {body}")
            continue
        note = ""
        auth = headers.get("WWW-Authenticate", "")
        if auth:
            realm = re.search(r'realm="([^"]+)"', auth)
            scheme = auth.split()[0] if auth else "?"
            note = f"  auth={scheme}"
            if realm:
                note += f"  realm=\"{realm.group(1)}\""
                verdicts.append(realm.group(1))
        server = headers.get("Server")
        if server:
            note += f"  server={server}"
        print(f"  {label:22} {status}{note}")

        if path == "/" and status == 200:
            title = re.search(r"<title[^>]*>(.*?)</title>", body,
                              re.I | re.S)
            if title:
                page = title.group(1).strip()
                print(f"  {'page title':22} {page!r}")
                verdicts.append(page)
        if status == 200 and "=" in body and path.startswith("/cgi-bin"):
            for line in body.strip().splitlines()[:6]:
                print(f"      {line.strip()}")
            verdicts.append("dahua-cgi-open")

    print(f"\n{RULE}\nVERDICT\n{RULE}")
    blob = " ".join(verdicts).lower()
    signals = []
    if dahua_cgi:
        signals.append("the Dahua CGI endpoint exists (401, not 404)")
    if 37777 in ports:
        signals.append("port 37777 open - Dahua's SDK port")
    if 37810 in ports:
        signals.append("port 37810 open - Dahua discovery")
    if re.search(r"Login to [0-9a-f]{32}", " ".join(verdicts)):
        signals.append("auth realm matches Dahua's format")
    if "dahua" in blob or "itc" in blob:
        signals.append("name mentions Dahua/ITC")

    if signals:
        print("  This IS a DAHUA device:")
        for s in signals:
            print(f"    - {s}")
        print("\n  A different-looking UI means different firmware (the Web 5.0")
        print("  interface looks nothing like the older one), and different")
        print("  credentials mean a different unit or a reset.")
        print("  Either way it is not the camera you know at work.")
    elif "hikvision" in blob or 8000 in ports:
        print("  Looks like a HIKVISION device - not a Dahua camera.")
    else:
        print("  Nothing Dahua-specific answered - no 37777, and the Dahua CGI")
        print("  returned 404 rather than 401. This is most likely a router,")
        print("  switch, NVR or other appliance, not the camera.")
        if verdicts:
            print(f"  Identity hints: {verdicts}")

    print("\n  Compare the MAC above against the label on the camera itself.")
    print("  That is the only check that cannot be fooled by a lookalike UI.")


if __name__ == "__main__":
    main()

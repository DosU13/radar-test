"""Find a Dahua camera on a direct Ethernet link.

Run this on the laptop the camera is plugged into. Only needs the standard
library - no pip install.

    python find_camera.py

A direct cable means no DHCP server, so the laptop falls back to a 169.254.x.x
link-local address while the camera keeps whatever static IP it was given.
They are on different subnets and cannot talk until you fix that, which is why
plain ping usually finds nothing.

This tries, in order:
  1. Dahua's UDP discovery broadcast (works across mismatched subnets)
  2. A passive listen - cameras announce themselves periodically
  3. A direct HTTP probe of the addresses this model is likely to be on

Then it tells you exactly what to set the laptop's IP to.
"""
import argparse
import json
import socket
import struct
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor

DISCOVERY_PORT = 37810
RULE = "-" * 68

# Worth trying before any scan: the address our unit uses, and the Dahua
# factory default that an un-provisioned or reset camera falls back to.
CANDIDATES = [
    ("172.17.83.60", "the camera we already know"),
    ("192.168.1.108", "Dahua factory default"),
    ("192.168.1.110", "common alternate default"),
    ("192.168.0.108", "factory default, 192.168.0.x variant"),
]


def local_addresses():
    """Every IPv4 address this machine holds, via ipconfig/ifconfig."""
    found = []
    try:
        if sys.platform == "win32":
            out = subprocess.run(["ipconfig"], capture_output=True, text=True,
                                 timeout=15).stdout
        else:
            out = subprocess.run(["ip", "-4", "addr"], capture_output=True,
                                 text=True, timeout=15).stdout
        import re
        found = re.findall(r"(\d{1,3}(?:\.\d{1,3}){3})", out)
    except Exception:
        pass
    return [a for a in found
            if not a.startswith(("127.", "255.")) and a != "0.0.0.0"]


def dhip_packet():
    """Dahua's DHIP discovery probe: 32-byte header plus a JSON body."""
    body = json.dumps({"method": "DHDiscover.search",
                       "params": {"mac": "", "uuid": ""}}).encode()
    header = (b"\x20\x00\x00\x00" + b"DHIP" + b"\x00" * 8
              + struct.pack("<I", len(body)) + b"\x00" * 4
              + struct.pack("<I", len(body)) + b"\x00" * 4)
    return header + body


def harvest(sock, seen, deadline, mine=()):
    """Read replies until the deadline, pulling any IP out of the JSON.

    Our own broadcast comes straight back to us, so skip this machine's
    addresses or every run "finds" the laptop.
    """
    while time.time() < deadline:
        sock.settimeout(max(0.2, deadline - time.time()))
        try:
            data, addr = sock.recvfrom(8192)
        except (socket.timeout, OSError):
            continue
        text = data.decode("utf-8", errors="replace")
        start = text.find("{")
        info = {}
        if start != -1:
            try:
                info = json.loads(text[start:])
            except json.JSONDecodeError:
                info = {}
        params = (info.get("params") or {}).get("deviceInfo") or {}
        ip = params.get("IPv4Address", {}).get("IPAddress") or addr[0]
        if ip in seen or ip in mine:
            continue
        seen[ip] = {
            "from": addr[0],
            "type": params.get("DeviceType") or params.get("deviceType"),
            "mac": (params.get("IPv4Address") or {}).get("PhysicalAddress"),
            "serial": params.get("SerialNo"),
        }
        print(f"  FOUND  {ip}"
              + (f"   {seen[ip]['type']}" if seen[ip]["type"] else "")
              + (f"   mac {seen[ip]['mac']}" if seen[ip]["mac"] else ""))


def discover(mine=(), seconds=6):
    print(RULE)
    print("1. DAHUA DISCOVERY BROADCAST")
    print(RULE)
    seen = {}
    packet = dhip_packet()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except OSError:
        sock.bind(("", 0))

    for target in ("255.255.255.255", "239.255.255.251"):
        for _ in range(2):
            try:
                sock.sendto(packet, (target, DISCOVERY_PORT))
            except OSError:
                pass
            time.sleep(0.2)

    harvest(sock, seen, time.time() + seconds, mine)
    sock.close()
    if not seen:
        print(f"  nothing answered in {seconds}s")
    return seen


def listen(mine=(), seconds=12):
    """Cameras announce themselves; just sit and watch for a while."""
    print()
    print(RULE)
    print(f"2. PASSIVE LISTEN ({seconds}s)")
    print(RULE)
    seen = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except OSError as exc:
        print(f"  cannot bind udp/{DISCOVERY_PORT}: {exc}")
        return seen
    harvest(sock, seen, time.time() + seconds, mine)
    sock.close()
    if not seen:
        print("  nothing announced itself")
    return seen


ONVIF_PROBE = """<?xml version="1.0" encoding="UTF-8"?>
<e:Envelope xmlns:e="http://www.w3.org/2003/05/soap-envelope"
 xmlns:w="http://schemas.xmlsoap.org/ws/2004/08/addressing"
 xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
 xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
<e:Header><w:MessageID>uuid:2ab3f1a0-0000-0000-0000-000000000001</w:MessageID>
<w:To e:mustUnderstand="true">urn:schemas-xmlsoap-org:ws:2005:04:discovery</w:To>
<w:Action e:mustUnderstand="true">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</w:Action>
</e:Header><e:Body><d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>
</e:Body></e:Envelope>"""


def onvif_discover(mine=(), seconds=6):
    """WS-Discovery on 239.255.255.250:3702 - the ONVIF standard probe.

    Nearly every IP camera answers this, and it crosses mismatched subnets
    because it is multicast, so it works on a direct cable.
    """
    import re
    print()
    print(RULE)
    print("2. ONVIF WS-DISCOVERY")
    print(RULE)
    seen = {}
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
    sock.settimeout(1.0)
    try:
        sock.bind(("", 0))
        for _ in range(2):
            sock.sendto(ONVIF_PROBE.encode(), ("239.255.255.250", 3702))
            time.sleep(0.3)
    except OSError as exc:
        print(f"  could not send probe: {exc}")
        sock.close()
        return seen

    deadline = time.time() + seconds
    while time.time() < deadline:
        sock.settimeout(max(0.2, deadline - time.time()))
        try:
            data, addr = sock.recvfrom(16384)
        except (socket.timeout, OSError):
            continue
        text = data.decode("utf-8", errors="replace")
        # The device lists its own service URLs; pull the addresses out.
        urls = re.findall(r"https?://(\d{1,3}(?:\.\d{1,3}){3})", text)
        for ip in set(urls + [addr[0]]):
            if ip in mine or ip in seen:
                continue
            model = re.search(r"hardware/([^\s<]+)", text)
            seen[ip] = {"type": model.group(1) if model else None}
            print(f"  FOUND  {ip}"
                  + (f"   {seen[ip]['type']}" if seen[ip]["type"] else ""))
    sock.close()
    if not seen:
        print(f"  nothing answered in {seconds}s")
    return seen


def sniff(local_ip, seconds=20):
    """Promiscuous IP capture - shows whatever the camera emits, any subnet.

    Windows raw sockets with SIO_RCVALL need an elevated prompt. This sees
    IP traffic only, not ARP, but cameras chatter enough (multicast
    announcements, NTP, DNS) to give themselves away quickly.
    """
    print()
    print(RULE)
    print(f"3. PASSIVE SNIFF ON {local_ip} ({seconds}s)")
    print(RULE)
    seen = {}
    try:
        raw = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        raw.bind((local_ip, 0))
        raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        raw.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
    except (AttributeError, OSError) as exc:
        print(f"  unavailable: {exc}")
        print("  (needs an ADMIN prompt on Windows - re-run elevated for this step)")
        return seen

    deadline = time.time() + seconds
    while time.time() < deadline:
        raw.settimeout(max(0.2, deadline - time.time()))
        try:
            packet, _ = raw.recvfrom(65535)
        except (socket.timeout, OSError):
            continue
        if len(packet) < 20:
            continue
        src = ".".join(str(b) for b in packet[12:16])
        dst = ".".join(str(b) for b in packet[16:20])
        if src in seen or src == local_ip or src.startswith("127."):
            continue
        seen[src] = {"to": dst}
        print(f"  SAW  {src:16} -> {dst}")
    try:
        raw.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
    except OSError:
        pass
    raw.close()
    if not seen:
        print("  no IP traffic seen - the camera may only be sending ARP")
    return seen


DAHUA_OUIS = {"bc:32:5f", "3c:ef:8c", "4c:11:bf", "e0:50:8b", "90:02:a9",
              "08:ed:ed", "24:52:6a", "38:af:29", "9c:14:63", "a0:bd:1d"}


def arp_lookup():
    """Whatever is in the ARP cache right now: {ip: mac}."""
    table = {}
    try:
        cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-n"]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=20).stdout
        import re
        for line in out.splitlines():
            ip = re.search(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", line)
            mac = re.search(r"\b(?:[0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}\b", line)
            if ip and mac:
                table[ip.group(0)] = mac.group(0).lower().replace("-", ":")
    except Exception:
        pass
    return table


def expand(prefix):
    """'192.168.1' -> a /24. '192.168' -> a /16. Returns (targets, label)."""
    parts = [p for p in prefix.strip().rstrip(".").split(".") if p]
    if len(parts) == 3:
        base = ".".join(parts)
        return [f"{base}.{n}" for n in range(1, 255)], f"{base}.1-254"
    if len(parts) == 2:
        base = ".".join(parts)
        return ([f"{base}.{third}.{n}"
                 for third in range(0, 256) for n in range(1, 255)],
                f"{base}.0-255.1-254")
    raise ValueError("give two or three octets, e.g. 192.168 or 192.168.1")


def sweep(prefix, timeout=0.4, want_mac=None):
    """Scan every address in the range. Never stops early - lists them all."""
    targets, label = expand(prefix)
    print()
    print(RULE)
    print(f"SWEEPING {label} on tcp/80   ({len(targets)} addresses)")
    if len(targets) > 5000:
        print("  a /16 takes a few minutes - leave it running")
    print(RULE)

    hits = []
    done = 0
    workers = 256 if len(targets) > 5000 else 128
    with ThreadPoolExecutor(max_workers=workers) as pool:
        for ip, ok in zip(targets,
                          pool.map(lambda a: http_probe(a, timeout), targets)):
            done += 1
            if ok:
                print(f"  OPEN  {ip}")
                hits.append(ip)
            if len(targets) > 5000 and done % 5000 == 0:
                print(f"    ...{done}/{len(targets)} checked, "
                      f"{len(hits)} found so far")

    print()
    print(RULE)
    print(f"RESULT: {len(hits)} host(s) listening on tcp/80")
    print(RULE)
    if not hits:
        print("  nothing found in that range")
        return hits

    # Contacting them populates the ARP cache, so vendors can be named.
    table = arp_lookup()
    for ip in hits:
        mac = table.get(ip)
        tag = ""
        if mac:
            oui = mac[:8]
            if want_mac and mac == want_mac.lower().replace("-", ":"):
                tag = "   <<< THIS IS THE MAC YOU ARE LOOKING FOR"
            elif oui in DAHUA_OUIS:
                tag = "   (Dahua OUI)"
            print(f"  {ip:16} {mac}{tag}")
        else:
            print(f"  {ip:16} {'(not in arp cache)':18}")
    return hits


def http_probe(ip, timeout=1.5):
    """Is something serving HTTP here? Cheap TCP connect, no auth needed."""
    try:
        with socket.create_connection((ip, 80), timeout=timeout):
            return True
    except OSError:
        return False


def probe_candidates(extra):
    print()
    print(RULE)
    print("3. PROBING LIKELY ADDRESSES (tcp/80)")
    print(RULE)
    targets = [(ip, why) for ip, why in CANDIDATES]
    targets += [(ip, "found above") for ip in extra if ip not in dict(targets)]
    hits = []
    with ThreadPoolExecutor(max_workers=16) as pool:
        results = list(pool.map(lambda t: (t[0], t[1], http_probe(t[0])), targets))
    for ip, why, ok in results:
        print(f"  {'OPEN' if ok else '    '}  {ip:16} {why}")
        if ok:
            hits.append(ip)
    return hits


def arp_table():
    print()
    print(RULE)
    print("4. ARP TABLE (anything that replied)")
    print(RULE)
    try:
        cmd = ["arp", "-a"] if sys.platform == "win32" else ["arp", "-n"]
        out = subprocess.run(cmd, capture_output=True, text=True,
                             timeout=15).stdout
        for line in out.splitlines():
            if line.strip() and "ff-ff-ff" not in line.lower() \
                    and "224." not in line and "239." not in line \
                    and "255.255.255.255" not in line:
                print("  " + line.strip())
    except Exception as exc:
        print(f"  could not read arp table: {exc}")


def advise(local, hits, discovered):
    print()
    print(RULE)
    print("WHAT TO DO")
    print(RULE)
    linklocal = [a for a in local if a.startswith("169.254.")]

    if hits or discovered:
        for ip in sorted(set(hits) | set(discovered)):
            print(f"  Camera looks like: {ip}")
            print(f"    python radar_check.py {ip}")
            octets = ip.split(".")
            print(f"    if it does not answer, give the laptop an address on "
                  f"that subnet, e.g. {'.'.join(octets[:3])}.50 / 255.255.255.0")
        return

    print("  Nothing found. On a direct cable that usually means the laptop and")
    print("  the camera are on different subnets, so nothing can reach anything.")
    if linklocal:
        print(f"\n  Your laptop is on {linklocal[0]} - a link-local address, which")
        print("  confirms there is no DHCP server on this cable. Expected.")
    print("\n  Add candidate addresses to the adapter, then re-run this script.")
    print("  Windows, in an ADMIN PowerShell (adapter name from 'Get-NetAdapter'):")
    print()
    print('    netsh interface ip add address "Ethernet" 192.168.1.50 255.255.255.0')
    print('    netsh interface ip add address "Ethernet" 172.17.83.50 255.255.255.0')
    print()
    print("  Both can coexist, so you can cover two guesses at once. Then:")
    print("    ping 192.168.1.108")
    print("    ping 172.17.83.60")
    print()
    print("  To undo afterwards:")
    print('    netsh interface ip delete address "Ethernet" 192.168.1.50')
    print('    netsh interface ip delete address "Ethernet" 172.17.83.50')
    print()
    print("  Still nothing? The camera may use a subnet you have not guessed.")
    print("  Dahua's own ConfigTool finds devices regardless of subnet, and")
    print("  a factory reset (button held ~10s) returns it to 192.168.1.108.")


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--listen", type=int, default=12,
                        help="passive listen seconds (default 12)")
    parser.add_argument("--quick", action="store_true",
                        help="skip the passive listen")
    parser.add_argument("--sniff", type=int, metavar="SECONDS",
                        help="promiscuous capture (needs an admin prompt)")
    parser.add_argument("--sweep", metavar="PREFIX",
                        help="scan for tcp/80. Two octets = /16 (192.168), "
                             "three = /24 (192.168.1). Lists every hit.")
    parser.add_argument("--mac", metavar="AA:BB:CC:DD:EE:FF",
                        help="flag this MAC in the results, e.g. BC:32:5F:D7:2F:07")
    args = parser.parse_args()

    local = local_addresses()
    print(f"\nthis machine: {', '.join(local) if local else 'no addresses found'}\n")

    if args.sweep:
        try:
            sweep(args.sweep, want_mac=args.mac)
        except ValueError as exc:
            print(f"  {exc}")
        return

    found = discover(mine=set(local))
    found.update(onvif_discover(mine=set(local)))
    if args.sniff and local:
        found.update(sniff(local[0], args.sniff))
    if not args.quick:
        found.update(listen(mine=set(local), seconds=args.listen))
    hits = probe_candidates(found.keys())
    arp_table()
    advise(local, hits, list(found.keys()))


if __name__ == "__main__":
    main()

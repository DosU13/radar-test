"""Find a camera's IP by listening for its ARP packets. Windows, admin needed.

    python arp_find.py              # capture 45s, report what it saw
    python arp_find.py --seconds 90

Why this works when nothing else does: a direct cable has no DHCP, so your
laptop falls back to 169.254.x.x while the camera keeps its static IP. They
are on different subnets and cannot exchange a single IP packet - which is why
ping, port scans and HTTP probes all find nothing.

ARP is different. It sits below IP and ignores subnets entirely, and every ARP
request a device sends carries its OWN address as the sender. The camera ARPs
for its gateway on its own schedule, so you just have to listen.

Uses pktmon, built into Windows 10/11 - nothing to install.
"""
import argparse
import ctypes
import os
import re
import subprocess
import sys
import tempfile
import time

RULE = "-" * 68
IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
MAC = re.compile(r"\b(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}\b")


def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run(args, timeout=120):
    return subprocess.run(args, capture_output=True, text=True, timeout=timeout)


def local_ips():
    out = run(["ipconfig"]).stdout
    return set(IPV4.findall(out))


def capture(seconds, etl):
    print(f"{RULE}\nCAPTURING ARP FOR {seconds}s\n{RULE}")
    run(["pktmon", "filter", "remove"])
    add = run(["pktmon", "filter", "add", "ARPonly", "-d", "ARP"])
    if add.returncode != 0:
        print(f"  could not add filter: {add.stdout.strip()} {add.stderr.strip()}")
        return False

    started = run(["pktmon", "start", "--capture", "--comp", "nics",
                   "--pkt-size", "128", "--file-name", etl])
    if started.returncode != 0:
        print(f"  could not start: {started.stdout.strip()} {started.stderr.strip()}")
        return False

    print("  listening... the camera ARPs on its own schedule, so give it time.")
    for remaining in range(seconds, 0, -5):
        print(f"    {remaining:3}s left", end="\r", flush=True)
        time.sleep(min(5, remaining))
    print(" " * 30, end="\r")

    run(["pktmon", "stop"])
    run(["pktmon", "filter", "remove"])
    return True


def decode(etl):
    txt = etl.replace(".etl", ".txt")
    result = run(["pktmon", "etl2txt", etl, "-v", "5", "-o", txt], timeout=180)
    if not os.path.exists(txt):
        # Older builds write alongside the etl without honouring -o.
        guess = etl[:-4] + ".txt"
        txt = guess if os.path.exists(guess) else None
    if not txt:
        print(f"  could not decode: {result.stdout.strip()}")
        return ""
    with open(txt, encoding="utf-8", errors="replace") as handle:
        return handle.read()


def report(text, mine):
    print(f"\n{RULE}\nWHAT ANSWERED\n{RULE}")
    if not text.strip():
        print("  the capture was empty - no ARP seen at all.")
        print("  Check the cable is in, the camera has power, and the adapter")
        print("  shows a link. 'Get-NetAdapter' should say Up.")
        return []

    def usable(ip):
        return not (ip in mine or ip.startswith(("127.", "0.", "255."))
                    or ip.endswith(".255"))

    ips, macs, senders = {}, set(), {}
    for line in text.splitlines():
        if "arp" not in line.lower():
            continue
        # "who-has X tell Y": Y is the device's own address - that is the one
        # we want. X is only the gateway it is hunting for.
        tell = re.search(r"tell\s+((?:\d{1,3}\.){3}\d{1,3})", line, re.I)
        if tell and usable(tell.group(1)):
            senders[tell.group(1)] = senders.get(tell.group(1), 0) + 1
        for ip in IPV4.findall(line):
            if usable(ip):
                ips[ip] = ips.get(ip, 0) + 1
        macs.update(m.lower().replace("-", ":") for m in MAC.findall(line))

    # A confirmed sender outranks anything merely mentioned in a packet.
    for ip, count in senders.items():
        ips[ip] = ips.get(ip, 0) + count * 100

    if not ips:
        print("  ARP packets were captured, but no address looked like a")
        print("  candidate. Try a longer --seconds, or check the .txt by hand.")
        return []

    print(f"  {'address':18} {'seen':>5}")
    for ip, count in sorted(ips.items(), key=lambda kv: -kv[1]):
        print(f"  {ip:18} {count:>5}")
    if macs:
        print(f"\n  MACs seen: {', '.join(sorted(macs)[:8])}")
        print("  Compare the OUI against the label on the camera.")
    return sorted(ips, key=lambda i: -ips[i])


def advise(candidates, mine):
    print(f"\n{RULE}\nNEXT\n{RULE}")
    if not candidates:
        return
    best = candidates[0]
    octets = best.split(".")
    subnet = ".".join(octets[:3])
    print(f"  Most likely camera address: {best}")
    print(f"\n  Put the laptop on that subnet (ADMIN PowerShell, adapter name")
    print(f"  from 'Get-NetAdapter'):")
    print(f'    netsh interface ip add address "Ethernet" {subnet}.50 255.255.255.0')
    print(f"\n  Then:")
    print(f"    ping {best}")
    print(f"    python whatis.py {best}")
    print(f"    python radar_check.py {best}")
    print(f"\n  Undo afterwards:")
    print(f'    netsh interface ip delete address "Ethernet" {subnet}.50')


def main():
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--seconds", type=int, default=45)
    parser.add_argument("--keep", action="store_true",
                        help="keep the capture files for inspection")
    args = parser.parse_args()

    if sys.platform != "win32":
        print("This uses pktmon, which is Windows-only.")
        print("On Linux/macOS: sudo tcpdump -i <iface> -n arp")
        sys.exit(1)
    if not is_admin():
        print("\n  pktmon needs an ELEVATED prompt.")
        print("  Right-click PowerShell -> Run as administrator, then re-run.")
        sys.exit(1)

    mine = local_ips()
    print(f"\nthis machine: {', '.join(sorted(mine)) or 'none'}\n")

    folder = tempfile.mkdtemp(prefix="arpfind_")
    etl = os.path.join(folder, "arp.etl")
    if not capture(args.seconds, etl):
        sys.exit(1)
    text = decode(etl)
    candidates = report(text, mine)
    advise(candidates, mine)
    if args.keep:
        print(f"\n  capture kept in {folder}")


if __name__ == "__main__":
    main()

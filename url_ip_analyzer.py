#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║           URL IP ANALYZER — Cybersecurity Recon Tool         ║
║                  Made by Monish Paramasivam                  ║
║         For ethical cybersecurity purposes only              ║
╚══════════════════════════════════════════════════════════════╝

Description:
    Accepts a URL, extracts domain/subdomain, resolves to IP,
    fetches IP intelligence (location, ISP, ASN), optionally runs
    an nmap scan, and presents findings in a clean CLI report.

Usage:
    python3 url_ip_analyzer.py
    python3 url_ip_analyzer.py --url https://example.com
    python3 url_ip_analyzer.py --url https://example.com --nmap --save

Requirements:
    pip install requests rich
    (nmap must be installed on the system for scan feature)
"""

import argparse
import json
import re
import socket
import subprocess
import sys
from datetime import datetime
from urllib.parse import urlparse

# ── Third-party (install via pip) ─────────────────────────────
try:
    import requests
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich.text import Text
    from rich import print as rprint
except ImportError:
    print("[!] Missing dependencies. Run: pip install requests rich")
    sys.exit(1)

# ── Global console ─────────────────────────────────────────────
console = Console()

# ══════════════════════════════════════════════════════════════
#  SECTION 1 — BANNER
# ══════════════════════════════════════════════════════════════

def print_banner():
    """Print the tool banner."""
    banner = """
[bold cyan]
 ██╗   ██╗██████╗ ██╗         ██╗██████╗      █████╗ ███╗   ██╗ █████╗ ██╗  ██╗   ██╗███████╗███████╗██████╗
 ██║   ██║██╔══██╗██║         ██║██╔══██╗    ██╔══██╗████╗  ██║██╔══██╗██║  ╚██╗ ██╔╝╚══███╔╝██╔════╝██╔══██╗
 ██║   ██║██████╔╝██║         ██║██████╔╝    ███████║██╔██╗ ██║███████║██║   ╚████╔╝   ███╔╝ █████╗  ██████╔╝
 ██║   ██║██╔══██╗██║         ██║██╔═══╝     ██╔══██║██║╚██╗██║██╔══██║██║    ╚██╔╝   ███╔╝  ██╔══╝  ██╔══██╗
 ╚██████╔╝██║  ██║███████╗    ██║██║         ██║  ██║██║ ╚████║██║  ██║███████╗██║   ███████╗███████╗██║  ██║
  ╚═════╝ ╚═╝  ╚═╝╚══════╝    ╚═╝╚═╝         ╚═╝  ╚═╝╚═╝  ╚═══╝╚═╝  ╚═╝╚══════╝╚═╝   ╚══════╝╚══════╝╚═╝  ╚═╝
[/bold cyan]"""
    console.print(banner)
    console.print(
        Panel(
            "[bold white]Made by [bold green]Monish Paramasivam[/bold green]  |  "
            "[bold yellow]Ethical Cybersecurity Recon Tool[/bold yellow]  |  "
            "[bold red]Use Responsibly[/bold red][/bold white]",
            style="cyan",
            box=box.DOUBLE,
        )
    )
    console.print()


# ══════════════════════════════════════════════════════════════
#  SECTION 2 — URL PARSING
# ══════════════════════════════════════════════════════════════

def parse_url(raw_url: str) -> dict:
    """
    Parse a raw URL and extract scheme, full domain, subdomain,
    root domain, and path.

    Args:
        raw_url: The URL string entered by the user.

    Returns:
        dict with keys: scheme, full_domain, subdomain, root_domain, path
    """
    # Add scheme if missing so urlparse works correctly
    if not re.match(r'^https?://', raw_url, re.IGNORECASE):
        raw_url = "http://" + raw_url

    parsed = urlparse(raw_url)
    full_domain = parsed.netloc or parsed.path  # fallback for bare domains

    # Strip port if present (e.g., example.com:8080)
    full_domain = full_domain.split(":")[0].strip()

    if not full_domain:
        raise ValueError(f"Could not extract a domain from: {raw_url}")

    # Split domain into parts to find subdomain vs root domain
    parts = full_domain.split(".")

    if len(parts) >= 3:
        # e.g., sub.example.com → subdomain=sub, root=example.com
        subdomain = ".".join(parts[:-2])
        root_domain = ".".join(parts[-2:])
    elif len(parts) == 2:
        # e.g., example.com → no subdomain
        subdomain = ""
        root_domain = full_domain
    else:
        subdomain = ""
        root_domain = full_domain

    return {
        "scheme":      parsed.scheme,
        "full_domain": full_domain,
        "subdomain":   subdomain,
        "root_domain": root_domain,
        "path":        parsed.path or "/",
        "original":    raw_url,
    }


# ══════════════════════════════════════════════════════════════
#  SECTION 3 — DNS RESOLUTION
# ══════════════════════════════════════════════════════════════

def resolve_domain(domain: str) -> str:
    """
    Resolve a domain name to its IPv4 address using Python's
    socket library.

    Args:
        domain: The fully-qualified domain name.

    Returns:
        IP address string, e.g., "93.184.216.34"

    Raises:
        socket.gaierror: If DNS resolution fails.
    """
    try:
        ip = socket.gethostbyname(domain)
        return ip
    except socket.gaierror as exc:
        raise ConnectionError(
            f"DNS resolution failed for '{domain}': {exc}"
        ) from exc


# ══════════════════════════════════════════════════════════════
#  SECTION 4 — IP INTELLIGENCE (ipinfo.io)
# ══════════════════════════════════════════════════════════════

def fetch_ip_intel(ip: str) -> dict:
    """
    Fetch IP intelligence from ipinfo.io (free, no API key needed
    for basic usage — up to 50k req/month).

    Returns a dict with: ip, city, region, country, org, asn,
    hostname, timezone, loc (lat,long).
    """
    url = f"https://ipinfo.io/{ip}/json"
    try:
        resp = requests.get(url, timeout=10)
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.ConnectionError:
        raise ConnectionError("Cannot reach ipinfo.io. Check your internet connection.")
    except requests.exceptions.Timeout:
        raise TimeoutError("ipinfo.io request timed out.")
    except requests.exceptions.HTTPError as exc:
        raise RuntimeError(f"ipinfo.io returned an error: {exc}")

    # Extract ASN from org field (format: "AS12345 Cloudflare, Inc.")
    org_raw  = data.get("org", "")
    asn      = ""
    org_name = org_raw
    if org_raw.startswith("AS"):
        parts    = org_raw.split(" ", 1)
        asn      = parts[0]                          # e.g., "AS13335"
        org_name = parts[1] if len(parts) > 1 else org_raw

    return {
        "ip":       data.get("ip", ip),
        "hostname": data.get("hostname", "N/A"),
        "city":     data.get("city", "N/A"),
        "region":   data.get("region", "N/A"),
        "country":  data.get("country", "N/A"),
        "loc":      data.get("loc", "N/A"),
        "org":      org_name,
        "asn":      asn,
        "timezone": data.get("timezone", "N/A"),
        "raw":      data,
    }


# ══════════════════════════════════════════════════════════════
#  SECTION 5 — NMAP SCAN
# ══════════════════════════════════════════════════════════════

# Common port-to-service descriptions for the explanation section
PORT_DESCRIPTIONS = {
    21:   ("FTP",        "File Transfer Protocol — often unencrypted; potential data interception risk."),
    22:   ("SSH",        "Secure Shell — remote login. Check for weak credentials or outdated versions."),
    23:   ("Telnet",     "Telnet — plaintext remote access. Highly insecure; should be disabled."),
    25:   ("SMTP",       "Mail server — could be misconfigured as open relay."),
    53:   ("DNS",        "Domain Name System — open DNS resolvers can be abused for amplification attacks."),
    80:   ("HTTP",       "Unencrypted web server — traffic is visible in transit."),
    110:  ("POP3",       "Mail retrieval — unencrypted by default."),
    143:  ("IMAP",       "Email access protocol — plaintext variant, check for TLS."),
    443:  ("HTTPS",      "Encrypted web traffic — generally safe; check certificate validity."),
    445:  ("SMB",        "Windows file sharing — historically targeted by ransomware (EternalBlue)."),
    3306: ("MySQL",      "Database port exposed — should NEVER be publicly accessible."),
    3389: ("RDP",        "Remote Desktop — common target for brute-force and ransomware delivery."),
    5432: ("PostgreSQL", "Database exposed — restrict access with firewall rules."),
    6379: ("Redis",      "In-memory DB — often misconfigured with no auth; high-risk if public."),
    8080: ("HTTP-Alt",   "Alternative HTTP port — often used by proxies or development servers."),
    8443: ("HTTPS-Alt",  "Alternative HTTPS port."),
    27017:("MongoDB",    "NoSQL database — frequently found unprotected in cloud deployments."),
}

def run_nmap(ip: str, fast: bool = True) -> str:
    """
    Run an nmap scan against the given IP using subprocess.

    Args:
        ip:   Target IP address.
        fast: If True, use -F (fast scan, top 100 ports).
              If False, scan top 1000 ports with service detection.

    Returns:
        Raw nmap output as a string.
    """
    # Check nmap is available
    try:
        subprocess.run(
            ["nmap", "--version"],
            capture_output=True,
            check=True
        )
    except (FileNotFoundError, subprocess.CalledProcessError):
        raise EnvironmentError(
            "nmap is not installed or not in PATH. "
            "Install it with: sudo apt install nmap"
        )

    flags = ["-F", "-sV", "--open", "-T4"] if fast else ["-sV", "--open", "-T4"]
    cmd   = ["nmap"] + flags + [ip]

    console.print(f"  [dim]Running:[/dim] [bold]{' '.join(cmd)}[/bold]")
    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120          # 2-minute cap
        )
        return result.stdout + result.stderr
    except subprocess.TimeoutExpired:
        return "[!] nmap scan timed out after 120 seconds."


def parse_nmap_output(raw: str) -> list[dict]:
    """
    Parse nmap stdout into a list of port records.

    Each record: { port, protocol, state, service, version }
    """
    records = []
    # Match lines like: 80/tcp   open  http    Apache httpd 2.4.41
    pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)"
    )
    for line in raw.splitlines():
        m = pattern.match(line.strip())
        if m:
            records.append({
                "port":     int(m.group(1)),
                "protocol": m.group(2),
                "state":    m.group(3),
                "service":  m.group(4),
                "version":  m.group(5).strip(),
            })
    return records


# ══════════════════════════════════════════════════════════════
#  SECTION 6 — RISK SCORING
# ══════════════════════════════════════════════════════════════

# High-risk ports that significantly raise the score
HIGH_RISK_PORTS  = {21, 23, 445, 3306, 3389, 6379, 27017, 5432}
MEDIUM_RISK_PORTS = {22, 25, 53, 80, 110, 143, 8080}

def calculate_risk(open_ports: list[dict]) -> tuple[str, str]:
    """
    Assign a risk level based on which ports are open.

    Returns:
        (level, color) — e.g., ("HIGH", "red")
    """
    if not open_ports:
        return "LOW", "green"

    port_nums = {p["port"] for p in open_ports}
    high_hits = port_nums & HIGH_RISK_PORTS
    med_hits  = port_nums & MEDIUM_RISK_PORTS

    if high_hits:
        return "HIGH", "bold red"
    elif len(med_hits) >= 2 or len(open_ports) >= 5:
        return "MEDIUM", "bold yellow"
    else:
        return "LOW", "bold green"


# ══════════════════════════════════════════════════════════════
#  SECTION 7 — HUMAN-READABLE EXPLANATION
# ══════════════════════════════════════════════════════════════

def generate_explanation(url_info: dict, ip_intel: dict,
                          open_ports: list[dict], risk: str) -> str:
    """
    Generate a plain-English explanation of what was found.
    """
    lines = []

    # What the IP represents
    org     = ip_intel.get("org", "an unknown organisation")
    country = ip_intel.get("country", "unknown country")
    city    = ip_intel.get("city", "")
    asn     = ip_intel.get("asn", "")
    loc_str = f"{city}, {country}" if city and city != "N/A" else country

    lines.append(
        f"The domain [bold]{url_info['full_domain']}[/bold] resolves to "
        f"[bold cyan]{ip_intel['ip']}[/bold cyan], which is hosted by "
        f"[bold]{org}[/bold] ({asn}) and is geographically located in "
        f"[bold]{loc_str}[/bold]."
    )

    if url_info["subdomain"]:
        lines.append(
            f"A subdomain '[bold]{url_info['subdomain']}[/bold]' was detected, "
            f"which may point to a specific service (e.g., API server, CDN node, mail server)."
        )

    lines.append("")  # blank line

    # Port explanations
    if open_ports:
        lines.append("[bold underline]Open Port Insights:[/bold underline]")
        for p in open_ports:
            num  = p["port"]
            svc  = p["service"]
            ver  = p["version"]
            desc_name, desc_text = PORT_DESCRIPTIONS.get(
                num, (svc, "Custom or unknown service. Investigate if unexpected.")
            )
            ver_note = f" (version: {ver})" if ver else ""
            lines.append(
                f"  • [bold yellow]Port {num}[/bold yellow] [{desc_name}]{ver_note}: {desc_text}"
            )
    else:
        lines.append("No open ports were detected (or nmap scan was skipped).")

    lines.append("")

    # Risk summary
    risk_advice = {
        "HIGH":   (
            "⚠️  [bold red]HIGH RISK:[/bold red] Critical ports are publicly exposed. "
            "Database ports, RDP, or legacy protocols like Telnet/FTP can be entry points "
            "for attackers. Immediate review and firewall hardening is strongly advised."
        ),
        "MEDIUM": (
            "⚡ [bold yellow]MEDIUM RISK:[/bold yellow] Some notable ports are open. "
            "Ensure all services are up-to-date, encrypted where possible, and access is "
            "restricted to authorised IPs only."
        ),
        "LOW": (
            "✅ [bold green]LOW RISK:[/bold green] No immediately critical ports detected. "
            "Continue to monitor, keep software patched, and enforce least-privilege access."
        ),
    }
    lines.append(risk_advice.get(risk, ""))
    lines.append("")
    lines.append(
        "[dim italic]Disclaimer: This scan is for authorised testing only. "
        "Scanning systems without explicit permission may be illegal.[/dim italic]"
    )

    return "\n".join(lines)


# ══════════════════════════════════════════════════════════════
#  SECTION 8 — DISPLAY FUNCTIONS
# ══════════════════════════════════════════════════════════════

def display_target_info(url_info: dict):
    """Print the Target Info section."""
    console.print(
        Panel("[bold white]① TARGET INFO[/bold white]",
              style="bold blue", box=box.HEAVY_HEAD)
    )
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Key",   style="bold cyan",  no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("Original URL",  url_info["original"])
    table.add_row("Scheme",        url_info["scheme"].upper() or "N/A")
    table.add_row("Full Domain",   url_info["full_domain"])
    table.add_row("Root Domain",   url_info["root_domain"])
    table.add_row("Subdomain",     url_info["subdomain"] or "[dim]None detected[/dim]")
    table.add_row("Path",          url_info["path"])

    console.print(table)
    console.print()


def display_ip_details(ip_intel: dict):
    """Print the IP Details section."""
    console.print(
        Panel("[bold white]② IP DETAILS[/bold white]",
              style="bold magenta", box=box.HEAVY_HEAD)
    )
    table = Table(show_header=False, box=box.SIMPLE, padding=(0, 2))
    table.add_column("Key",   style="bold cyan",  no_wrap=True)
    table.add_column("Value", style="white")

    table.add_row("IP Address", f"[bold yellow]{ip_intel['ip']}[/bold yellow]")
    table.add_row("Hostname",   ip_intel["hostname"])
    table.add_row("Country",    ip_intel["country"])
    table.add_row("Region",     ip_intel["region"])
    table.add_row("City",       ip_intel["city"])
    table.add_row("Coordinates",ip_intel["loc"])
    table.add_row("Timezone",   ip_intel["timezone"])
    table.add_row("ISP / Org",  ip_intel["org"])
    table.add_row("ASN",        ip_intel["asn"] or "[dim]N/A[/dim]")

    console.print(table)
    console.print()


def display_scan_results(open_ports: list[dict], risk: str, risk_color: str):
    """Print the Scan Results section."""
    console.print(
        Panel("[bold white]③ SCAN RESULTS[/bold white]",
              style="bold green", box=box.HEAVY_HEAD)
    )

    if not open_ports:
        console.print(
            "  [dim]No open ports found or scan was skipped.[/dim]\n"
        )
        return

    # Risk badge
    console.print(
        f"  Risk Level: [{risk_color}] {risk} [/{risk_color}]\n"
    )

    table = Table(
        show_header=True,
        header_style="bold white on dark_green",
        box=box.ROUNDED,
        padding=(0, 1),
    )
    table.add_column("Port",     style="bold yellow", no_wrap=True, justify="right")
    table.add_column("Protocol", style="cyan",        no_wrap=True)
    table.add_column("State",    style="bold green",  no_wrap=True)
    table.add_column("Service",  style="white",       no_wrap=True)
    table.add_column("Version",  style="dim")

    for p in open_ports:
        table.add_row(
            str(p["port"]),
            p["protocol"],
            p["state"],
            p["service"],
            p["version"] or "—",
        )

    console.print(table)
    console.print()


def display_explanation(explanation: str, risk: str, risk_color: str):
    """Print the Explanation section."""
    console.print(
        Panel("[bold white]④ EXPLANATION[/bold white]",
              style="bold red", box=box.HEAVY_HEAD)
    )
    console.print(explanation)
    console.print()


# ══════════════════════════════════════════════════════════════
#  SECTION 9 — SAVE RESULTS
# ══════════════════════════════════════════════════════════════

def save_results(url_info: dict, ip_intel: dict,
                 open_ports: list[dict], explanation: str,
                 risk: str, nmap_raw: str = ""):
    """
    Save all results to a timestamped JSON + text report.
    """
    ts       = datetime.now().strftime("%Y%m%d_%H%M%S")
    domain   = url_info["root_domain"].replace(".", "_")
    basename = f"url_ip_report_{domain}_{ts}"

    # ── JSON export ──────────────────────────────────────────
    json_path = f"{basename}.json"
    report_data = {
        "timestamp":  datetime.now().isoformat(),
        "target":     url_info,
        "ip_intel":   ip_intel,
        "open_ports": open_ports,
        "risk":       risk,
        "nmap_raw":   nmap_raw,
    }
    with open(json_path, "w") as f:
        json.dump(report_data, f, indent=2)

    # ── Text export ──────────────────────────────────────────
    txt_path = f"{basename}.txt"
    with open(txt_path, "w") as f:
        f.write("URL IP ANALYZER — Report\n")
        f.write(f"Generated: {datetime.now()}\n")
        f.write(f"Made by Monish Paramasivam\n")
        f.write("=" * 60 + "\n\n")

        f.write("TARGET INFO\n" + "-" * 40 + "\n")
        for k, v in url_info.items():
            f.write(f"  {k:15}: {v}\n")

        f.write("\nIP DETAILS\n" + "-" * 40 + "\n")
        for k, v in ip_intel.items():
            if k != "raw":
                f.write(f"  {k:12}: {v}\n")

        f.write(f"\nRISK LEVEL: {risk}\n")

        f.write("\nOPEN PORTS\n" + "-" * 40 + "\n")
        for p in open_ports:
            f.write(
                f"  {p['port']}/{p['protocol']:3}  {p['state']:6}  "
                f"{p['service']:12}  {p['version']}\n"
            )

        f.write("\nEXPLANATION\n" + "-" * 40 + "\n")
        # Strip rich markup for plain text
        plain_exp = re.sub(r"\[.*?\]", "", explanation)
        f.write(plain_exp + "\n")

        if nmap_raw:
            f.write("\nRAW NMAP OUTPUT\n" + "-" * 40 + "\n")
            f.write(nmap_raw + "\n")

    console.print(
        f"\n[bold green]✔ Results saved:[/bold green] "
        f"[cyan]{txt_path}[/cyan] and [cyan]{json_path}[/cyan]"
    )


# ══════════════════════════════════════════════════════════════
#  SECTION 10 — ARGUMENT PARSING
# ══════════════════════════════════════════════════════════════

def build_arg_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser."""
    parser = argparse.ArgumentParser(
        prog="url_ip_analyzer",
        description="URL IP Analyzer — Ethical Cybersecurity Recon Tool by Monish Paramasivam",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 url_ip_analyzer.py
  python3 url_ip_analyzer.py --url https://example.com
  python3 url_ip_analyzer.py --url https://sub.example.com --nmap --save
  python3 url_ip_analyzer.py --url http://evil.com --nmap --full
        """,
    )
    parser.add_argument(
        "--url", "-u",
        type=str,
        help="Target URL (e.g., https://example.com)"
    )
    parser.add_argument(
        "--nmap", "-n",
        action="store_true",
        help="Run an nmap scan on the resolved IP"
    )
    parser.add_argument(
        "--full", "-f",
        action="store_true",
        help="Run a full nmap scan (top 1000 ports) instead of fast mode"
    )
    parser.add_argument(
        "--save", "-s",
        action="store_true",
        help="Save results to JSON and TXT files"
    )
    return parser


# ══════════════════════════════════════════════════════════════
#  SECTION 11 — MAIN ORCHESTRATOR
# ══════════════════════════════════════════════════════════════

def main():
    """Entry point — orchestrates all analysis steps."""
    print_banner()

    parser  = build_arg_parser()
    args    = parser.parse_args()

    # ── Get URL ───────────────────────────────────────────────
    if args.url:
        raw_url = args.url.strip()
    else:
        raw_url = console.input(
            "[bold cyan]Enter the target URL[/bold cyan] "
            "[dim](e.g., https://example.com)[/dim]: "
        ).strip()

    if not raw_url:
        console.print("[bold red][!] No URL provided. Exiting.[/bold red]")
        sys.exit(1)

    console.print()

    # ── Step 1: Parse URL ─────────────────────────────────────
    with console.status("[bold cyan]Parsing URL...[/bold cyan]"):
        try:
            url_info = parse_url(raw_url)
        except ValueError as exc:
            console.print(f"[bold red][!] {exc}[/bold red]")
            sys.exit(1)

    display_target_info(url_info)

    # ── Step 2: Resolve DNS ───────────────────────────────────
    with console.status(
        f"[bold cyan]Resolving {url_info['full_domain']} → IP...[/bold cyan]"
    ):
        try:
            ip_address = resolve_domain(url_info["full_domain"])
            console.print(
                f"  [bold green]✔[/bold green] Resolved: "
                f"[bold yellow]{ip_address}[/bold yellow]\n"
            )
        except ConnectionError as exc:
            console.print(f"[bold red][!] {exc}[/bold red]")
            sys.exit(1)

    # ── Step 3: Fetch IP Intelligence ─────────────────────────
    with console.status("[bold cyan]Fetching IP intelligence from ipinfo.io...[/bold cyan]"):
        try:
            ip_intel = fetch_ip_intel(ip_address)
        except (ConnectionError, TimeoutError, RuntimeError) as exc:
            console.print(f"[bold red][!] IP intel error: {exc}[/bold red]")
            ip_intel = {
                "ip": ip_address, "hostname": "N/A", "city": "N/A",
                "region": "N/A", "country": "N/A", "loc": "N/A",
                "org": "N/A", "asn": "N/A", "timezone": "N/A", "raw": {}
            }

    display_ip_details(ip_intel)

    # ── Step 4: Optional nmap Scan ────────────────────────────
    open_ports = []
    nmap_raw   = ""

    if args.nmap:
        console.print(
            Panel(
                "[bold white]③ SCAN RESULTS[/bold white]",
                style="bold green", box=box.HEAVY_HEAD
            )
        )
        console.print(
            f"  [bold yellow]⚠  Scanning {ip_address} — "
            f"only scan systems you are authorised to test.[/bold yellow]\n"
        )
        with console.status("[bold cyan]Running nmap scan...[/bold cyan]"):
            try:
                nmap_raw   = run_nmap(ip_address, fast=not args.full)
                open_ports = parse_nmap_output(nmap_raw)
            except EnvironmentError as exc:
                console.print(f"  [bold red][!] {exc}[/bold red]")
            except Exception as exc:
                console.print(f"  [bold red][!] nmap error: {exc}[/bold red]")

        risk, risk_color = calculate_risk(open_ports)
        display_scan_results(open_ports, risk, risk_color)
    else:
        risk, risk_color = "LOW", "bold green"
        console.print(
            Panel("[bold white]③ SCAN RESULTS[/bold white]",
                  style="bold green", box=box.HEAVY_HEAD)
        )
        console.print(
            "  [dim]nmap scan skipped. Use [bold]--nmap[/bold] to enable it.[/dim]\n"
        )

    # ── Step 5: Generate & Display Explanation ────────────────
    explanation = generate_explanation(url_info, ip_intel, open_ports, risk)
    display_explanation(explanation, risk, risk_color)

    # ── Step 6: Optional Save ─────────────────────────────────
    if args.save:
        save_results(url_info, ip_intel, open_ports, explanation, risk, nmap_raw)
    else:
        save_prompt = console.input(
            "[bold cyan]Save results to file? [y/N]:[/bold cyan] "
        ).strip().lower()
        if save_prompt == "y":
            save_results(url_info, ip_intel, open_ports, explanation, risk, nmap_raw)

    # ── Footer ────────────────────────────────────────────────
    console.print(
        Panel(
            "[bold green]Scan complete.[/bold green]  "
            "[dim]Made by [bold white]Monish Paramasivam[/bold white] — "
            "Use this tool ethically and responsibly.[/dim]",
            style="dim cyan",
            box=box.ROUNDED,
        )
    )


# ══════════════════════════════════════════════════════════════
if __name__ == "__main__":
    main()

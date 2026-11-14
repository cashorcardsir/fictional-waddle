import base64
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

STREAM_URL = "https://dlhd.st/stream/stream-51.php"
SOURCE_URL = "https://uqload.vc/js2/x7qf3m2v.js"
BLOCKLIST_URL = "https://codeberg.org/jcoscia/evasive-ads-blocklist/raw/branch/main/adcash.txt"
XOR_KEY = b"xR9tB2pL6q7MwVe"

FILTERS_FILE = "filters.txt"
ADD_DOMAINS_FILE = "add-domains.txt"
MANUAL_START = "# BEGIN ADD-DOMAINS"
MANUAL_END = "# END ADD-DOMAINS"

DOMAIN_PATTERN = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
)


def fetch_text(url):
    """Fetch a URL; retry once after 45 seconds, then skip it."""
    for attempt in range(2):
        try:
            request = urllib.request.Request(
                url,
                headers={"User-Agent": "Mozilla/8.0"},
            )
            with urllib.request.urlopen(request, timeout=20) as response:
                return response.read().decode("utf-8")
        except Exception:
            if attempt == 0:
                time.sleep(45)

    return None


def load_existing_targets(path):
    """Load old non-manual filter entries, skipping the marked manual section."""
    targets = set()
    in_manual_section = False

    try:
        with open(path, encoding="utf-8") as existing:
            for line in existing:
                entry = line.strip()

                if entry == MANUAL_START:
                    in_manual_section = True
                    continue

                if entry == MANUAL_END:
                    in_manual_section = False
                    continue

                if in_manual_section or not entry or entry.startswith("#"):
                    continue

                entry = entry.removeprefix("||").removesuffix("^").strip("/")
                if entry:
                    targets.add(entry.lower())
    except FileNotFoundError:
        pass

    return targets


def load_add_domains(path):
    """Load valid plain-text domains, one per line."""
    domains = set()

    try:
        with open(path, encoding="utf-8") as source:
            for line in source:
                domain = line.strip().lower()
                if domain and DOMAIN_PATTERN.fullmatch(domain):
                    domains.add(domain)
    except FileNotFoundError:
        pass

    return domains


def parse_ip_address(value):
    """Return a validated, normalized IP address, or None if invalid."""
    if not isinstance(value, str) or not value.strip():
        return None

    try:
        return str(ipaddress.ip_address(value.strip()))
    except ValueError:
        return None


def extract_zone_ips(config):
    """Extract validated IPs from decoyDomainZones."""
    zones = config.get("decoyDomainZones")
    if not isinstance(zones, dict):
        return None

    addresses_found = set()

    for addresses in zones.values():
        if not isinstance(addresses, list):
            continue

        for address in addresses:
            parsed_ip = parse_ip_address(address)
            if parsed_ip:
                addresses_found.add(parsed_ip)

    return addresses_found


def extract_domains_from_text(text):
    """Extract domains from lines containing a domain or URL."""
    domains = set()

    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue

        entry = entry.removeprefix("||").removesuffix("^").strip()

        if "://" in entry:
            parsed = urlsplit(entry)
        else:
            parsed = urlsplit("//" + entry)

        host = parsed.hostname
        if host and DOMAIN_PATTERN.fullmatch(host):
            domains.add(host.lower())

    return domains


def fetch_tsd_domains():
    """Fetch domains from tsd.txt and tsd_m.txt beside SOURCE_URL."""
    domains = set()

    for filename in ("tsd.txt", "tsd_m.txt"):
        url = urljoin(SOURCE_URL, filename)
        text = fetch_text(url)
        if text:
            domains.update(extract_domains_from_text(text))

    return domains


def extract_stream_domains(source):
    domains = set()

    # Scan array assignments, regardless of variable name.
    for match in re.finditer(
        r"\b[A-Za-z_$][\w$]*\s*=\s*\[([^\]]*)\]",
        source,
    ):
        values = re.findall(
            r"""["']([A-Za-z0-9+/=]+)["']""",
            match.group(1),
        )

        for value in values:
            try:
                decoded = base64.b64decode(value, validate=True).decode("utf-8")
            except (ValueError, UnicodeDecodeError):
                continue

            host = urlsplit("//" + decoded).hostname
            if host:
                domains.add(host.lower())

    return domains


def extract_blocklist_domains(text):
    domains = set()

    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue

        # Accept plain domains and common adblock-style domain entries.
        entry = entry.removeprefix("||").removesuffix("^").strip("/")
        if DOMAIN_PATTERN.fullmatch(entry):
            domains.add(entry.lower())

    return domains


manual_targets = load_add_domains(ADD_DOMAINS_FILE)

# Preserve previously discovered entries, excluding the marked manual section.
targets = load_existing_targets(FILTERS_FILE) - manual_targets

# Remember old filter IPs so they can be replaced by the current JSON IPs
# if the config is successfully fetched and parsed.
previous_filter_ips = {
    parsed_ip
    for target in targets
    if (parsed_ip := parse_ip_address(target)) is not None
}

# Get domains and IPs from the XOR-encoded JavaScript value.
js_source = fetch_text(SOURCE_URL)
if js_source:
    match = re.search(
        r"""window\s*\[\s*(['"])[^'"]+\1\s*\]\s*=\s*(['"])(.*?)\2""",
        js_source,
    )

    if match:
        encoded = match.group(3)
        encoded += "=" * (-len(encoded) % 4)

        try:
            ciphertext = base64.b64decode(encoded, validate=True)
            plaintext = bytes(
                byte ^ XOR_KEY[index % len(XOR_KEY)]
                for index, byte in enumerate(ciphertext)
            )
            config = json.loads(plaintext.decode("utf-8"))

            for field in ("adserverDomain", "decoyDomain", "cdnDomain"):
                value = config.get(field)
                if isinstance(value, str) and value.strip():
                    targets.add(value.strip().lower())

            current_json_ips = extract_zone_ips(config)

            # A dict means the JSON contains an authoritative zone-IP list.
            # Replace prior filter IPs only after the config has decoded
            # successfully and decoyDomainZones has the expected dict format.
            if current_json_ips is not None:
                if previous_filter_ips != current_json_ips:
                    targets.difference_update(previous_filter_ips)
                    targets.update(current_json_ips)

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass

# Get Base64-encoded hostnames from the stream page.
stream_source = fetch_text(STREAM_URL)
if stream_source:
    try:
        targets.update(extract_stream_domains(stream_source))
    except Exception:
        pass

# Add domains from tsd.txt and tsd_m.txt, derived from SOURCE_URL's directory.
try:
    targets.update(fetch_tsd_domains())
except Exception:
    pass

# Add domains from the blocklist.
blocklist_text = fetch_text(BLOCKLIST_URL)
if blocklist_text:
    targets.update(extract_blocklist_domains(blocklist_text))

# Manual entries are included even if no other source succeeded.
targets.update(manual_targets)

if not targets:
    raise SystemExit("No targets were fetched; leaving filters.txt unchanged")


def check_target(target):
    try:
        ip = ipaddress.ip_address(target)
        host_for_url = f"[{target}]" if ip.version == 6 else target
        schemes = ("http",)
    except ValueError:
        host_for_url = target
        schemes = ("https", "http")

    for scheme in schemes:
        url = f"{scheme}://{host_for_url}/"

        # Try HEAD first, then a small ranged GET if HEAD fails.
        for method in ("HEAD", "GET"):
            request = urllib.request.Request(
                url,
                method=method,
                headers={
                    "User-Agent": "Mozilla/8.0",
                    "Range": "bytes=0-0",
                },
            )

            try:
                with urllib.request.urlopen(request, timeout=5):
                    return target
            except urllib.error.HTTPError:
                # Any HTTP status means the server responded.
                return target
            except Exception:
                # For example, HEAD may be unsupported; try GET next.
                continue

    return None


# Manual entries bypass the active check.
targets_to_check = targets - manual_targets

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, targets_to_check)
    active_targets = {target for target in results if target is not None}

# Include all current add-domains.txt entries, whether active or not.
active_targets.update(manual_targets)

with open(FILTERS_FILE, "w", encoding="utf-8") as output:
    # Write automatically sourced and checked entries outside the manual block.
    for target in sorted(active_targets - manual_targets):
        output.write(f"||{target}^\n")

    # Replace this marked section from add-domains.txt on each run.
    output.write(f"{MANUAL_START}\n")
    for target in sorted(manual_targets):
        output.write(f"||{target}^\n")
    output.write(f"{MANUAL_END}\n")

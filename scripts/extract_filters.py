import base64
import ipaddress
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

STREAM_URL = "https://dlhd.st/stream/stream-51.php"
SOURCE_URL = "https://uqload.vc/js2/x7qf3m2v.js"
BLOCKLIST_URL = "https://codeberg.org/jcoscia/evasive-ads-blocklist/raw/branch/main/adcash.txt"
XOR_KEY = b"xR9tB2pL6q7MwVe"

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


targets = set()

# Get Base64-encoded hostnames from the stream page.
stream_source = fetch_text(STREAM_URL)
if stream_source:
    try:
        targets.update(extract_stream_domains(stream_source))
    except Exception:
        pass

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

            zones = config.get("decoyDomainZones", {})
            if isinstance(zones, dict):
                for addresses in zones.values():
                    if isinstance(addresses, list):
                        for address in addresses:
                            if isinstance(address, str):
                                try:
                                    targets.add(
                                        str(ipaddress.ip_address(address.strip()))
                                    )
                                except ValueError:
                                    pass

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass

# Add domains from the Codeberg blocklist.
blocklist_text = fetch_text(BLOCKLIST_URL)
if blocklist_text:
    targets.update(extract_blocklist_domains(blocklist_text))

# Avoid replacing the existing file with an empty list if every source failed.
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
        request = urllib.request.Request(
            f"{scheme}://{host_for_url}/",
            method="HEAD",
            headers={"User-Agent": "Mozilla/8.0"},
        )

        try:
            with urllib.request.urlopen(request, timeout=5):
                return target
        except urllib.error.HTTPError:
            # An HTTP response, including 403 or 404, means it responded.
            return target
        except Exception:
            continue

    return None


# Check deduplicated targets concurrently; only responsive ones are written.
with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, targets)
    active_targets = {target for target in results if target is not None}

with open("filters.txt", "w", encoding="utf-8") as output:
    for target in sorted(active_targets):
        output.write(f"||{target}^\n")

import ast
import ipaddress
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor

SOURCE_URL = "https://uqload.vc/js2/x7qf3m2v.js"
XOR_KEY = "xR9tB2pL6q7MwVe"

def fetch_text(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adblock-list-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")

# Fetch JavaScript as text; never execute it.
source = fetch_text(SOURCE_URL)

# Find window['randomizedName'] = 'encoded string';
match = re.search(
    r"""window\s*\[\s*(['"])[^'"]+\1\s*\]\s*=\s*(['"])(.*?)\2\s*;""",
    source,
    re.DOTALL,
)
if not match:
    raise SystemExit("Could not find the window[...] string assignment")

quote, encoded_literal = match.group(2), match.group(3)

try:
    encoded_text = ast.literal_eval(quote + encoded_literal + quote)
except (SyntaxError, ValueError) as error:
    raise SystemExit(f"Could not parse the assigned string: {error}")

try:
    encoded_bytes = encoded_text.encode("latin-1")
    key_bytes = XOR_KEY.encode("ascii")
    decoded_bytes = bytes(
        byte ^ key_bytes[index % len(key_bytes)]
        for index, byte in enumerate(encoded_bytes)
    )
    config = json.loads(decoded_bytes.decode("utf-8"))
except (UnicodeError, ValueError, json.JSONDecodeError) as error:
    raise SystemExit(f"Could not XOR-decode and parse the configuration: {error}")

domains = set()
ips = set()

# Collect string values whose field names identify them as domains.
def collect_domains(value):
    if isinstance(value, dict):
        for key, child in value.items():
            if "domain" in key.lower() and isinstance(child, str):
                candidate = child.strip().lower().rstrip(".")
                if candidate:
                    domains.add(candidate)
            collect_domains(child)
    elif isinstance(value, list):
        for child in value:
            collect_domains(child)

collect_domains(config)

# Collect IP addresses specifically from decoyDomainZones.
zones = config.get("decoyDomainZones", {})
if isinstance(zones, dict):
    for addresses in zones.values():
        if isinstance(addresses, list):
            for address in addresses:
                try:
                    ips.add(str(ipaddress.ip_address(address)))
                except ValueError:
                    continue

targets = domains | ips
if not targets:
    raise SystemExit("No domains or IP addresses were found")

def check_target(target):
    # Try HTTPS and then HTTP. Any HTTP response counts as responsive.
    for scheme in ("https", "http"):
        request = urllib.request.Request(
            f"{scheme}://{target}/",
            method="HEAD",
            headers={"User-Agent": "adblock-list-check/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5):
                return target
        except urllib.error.HTTPError:
            return target
        except Exception:
            pass
    return None

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, targets)
    active_targets = {target for target in results if target is not None}

with open("filters.txt", "w", encoding="utf-8") as output:
    for target in sorted(active_targets):
        output.write(f"||{target}^\n")

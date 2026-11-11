import base64
import ipaddress
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

UQLOAD_URL = "https://uqload.vc/js2/x7qf3m2v.js"
XOR_KEY = b"xR9tB2pL6q7MwVe"


def fetch_text(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adblock-list-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


domains = set()

# Extract domains from Base64 arrays in the page saved as page.html.
with open("page.html", encoding="utf-8") as file:
    page_source = file.read()

for variable in ("v", "c", "g", "z"):
    match = re.search(
        rf"\b{variable}\s*=\s*\[([^\]]*)\]",
        page_source,
    )
    if not match:
        continue

    candidate_domains = set()
    values = re.findall(r'"([A-Za-z0-9+/=]+)"', match.group(1))

    for value in values:
        try:
            decoded = base64.b64decode(value, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            continue

        host = urlsplit("//" + decoded).hostname
        if host:
            candidate_domains.add(host.lower())

    # Use the first of v, c, g, z that contains usable Base64 domains.
    if candidate_domains:
        domains.update(candidate_domains)
        break

# Fetch and decode the UQLoad configuration.
try:
    uqload_source = fetch_text(UQLOAD_URL)
except Exception as error:
    raise SystemExit(f"Could not fetch the UQLoad script: {error}")

match = re.search(
    r"""window\s*\[\s*(['"])[^'"]+\1\s*\]\s*=\s*(['"])(.*?)\2""",
    uqload_source,
)
if not match:
    raise SystemExit("Could not find the window[...] assignment in the UQLoad script")

encoded = match.group(3)
encoded += "=" * (-len(encoded) % 4)

try:
    ciphertext = base64.b64decode(encoded, validate=True)
except ValueError as error:
    raise SystemExit(f"The UQLoad value is not valid Base64: {error}")

plaintext = bytes(
    byte ^ XOR_KEY[index % len(XOR_KEY)]
    for index, byte in enumerate(ciphertext)
)

try:
    config = json.loads(plaintext.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Could not decode the UQLoad value as JSON: {error}")

# Add domains from the decoded configuration.
for field in ("adserverDomain", "decoyDomain", "cdnDomain"):
    value = config.get(field)
    if isinstance(value, str) and value.strip():
        domains.add(value.strip().lower())

# Add IP addresses from decoyDomainZones.
targets = set(domains)
zones = config.get("decoyDomainZones", {})
if isinstance(zones, dict):
    for addresses in zones.values():
        if isinstance(addresses, list):
            for address in addresses:
                if isinstance(address, str):
                    try:
                        targets.add(str(ipaddress.ip_address(address.strip())))
                    except ValueError:
                        pass


def check_target(target):
    try:
        ipaddress.ip_address(target)
        schemes = ("http",)
    except ValueError:
        schemes = ("https", "http")

    for scheme in schemes:
        request = urllib.request.Request(
            f"{scheme}://{target}/",
            method="HEAD",
            headers={"User-Agent": "adblock-list-check/1.0"},
        )
        try:
            with urllib.request.urlopen(request, timeout=5):
                return target
        except urllib.error.HTTPError:
            # Any HTTP response, including 403 or 404, counts as responsive.
            return target
        except Exception:
            continue

    return None


with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, targets)
    active_targets = {target for target in results if target is not None}

with open("filters.txt", "w", encoding="utf-8") as output:
    for target in sorted(active_targets):
        output.write(f"||{target}^\n")

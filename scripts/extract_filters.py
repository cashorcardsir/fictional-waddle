import base64
import ipaddress
import json
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

STREAM_URL = "https://thedaddy.li/stream/stream-51.php"
SOURCE_URL = "https://uqload.vc/js2/x7qf3m2v.js"
XOR_KEY = b"xR9tB2pL6q7MwVe"


def fetch_text(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adblock-list-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")


def extract_stream_domains(source):
    # Check v, c, g, then z. Use the first array containing decodable
    # Base64 values that produce hostnames.
    for variable in ("v", "c", "g", "z"):
        match = re.search(
            rf"\b{variable}\s*=\s*\[([^\]]*)\]",
            source,
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

        if candidate_domains:
            return candidate_domains

    raise ValueError("No usable Base64 hostnames found in v, c, g, or z")


# Get domains from the stream page.
try:
    stream_source = fetch_text(STREAM_URL)
    targets = extract_stream_domains(stream_source)
except Exception as error:
    raise SystemExit(f"Could not extract domains from the stream page: {error}")

# Fetch the JavaScript and find window['randomizedName'] = 'encodedValue'.
try:
    js_source = fetch_text(SOURCE_URL)
except Exception as error:
    raise SystemExit(f"Could not fetch the JavaScript source: {error}")

match = re.search(
    r"""window\s*\[\s*(['"])[^'"]+\1\s*\]\s*=\s*(['"])(.*?)\2""",
    js_source,
)
if not match:
    raise SystemExit("Could not find the window[...] assignment")

encoded = match.group(3)
encoded += "=" * (-len(encoded) % 4)

try:
    ciphertext = base64.b64decode(encoded, validate=True)
except ValueError as error:
    raise SystemExit(f"The encoded value is not valid Base64: {error}")

plaintext = bytes(
    byte ^ XOR_KEY[index % len(XOR_KEY)]
    for index, byte in enumerate(ciphertext)
)

try:
    config = json.loads(plaintext.decode("utf-8"))
except (UnicodeDecodeError, json.JSONDecodeError) as error:
    raise SystemExit(f"Could not decode the XOR value as JSON: {error}")

# Add the domains from the decoded JSON.
for field in ("adserverDomain", "decoyDomain", "cdnDomain"):
    value = config.get(field)
    if isinstance(value, str) and value.strip():
        targets.add(value.strip().lower())

# Add IP addresses from decoyDomainZones.
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
            # An HTTP response, including 403 or 404, means it responded.
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

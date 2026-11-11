import base64
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

BLOCKLIST_URL = "https://codeberg.org/jcoscia/evasive-ads-blocklist/raw/branch/main/adcash.txt"

def fetch_text(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adblock-list-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")

# Read the page source that the workflow downloaded to page.html.
with open("page.html", encoding="utf-8") as file:
    page_source = file.read()

# Check v, c, g, then z. Use the first variable with Base64 values
# that decode to usable hostnames.
domains = set()

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

    if candidate_domains:
        domains = candidate_domains
        break

if not domains:
    raise SystemExit("Could not find Base64 values with usable hostnames in v, c, g, or z")

# Add domains from the additional line-by-line blocklist.
try:
    blocklist = fetch_text(BLOCKLIST_URL)
except Exception as error:
    raise SystemExit(f"Could not fetch the additional blocklist: {error}")

domain_pattern = re.compile(
    r"(?=.{1,253}$)"
    r"(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)"
    r"(?:\.[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*"
)

for line in blocklist.splitlines():
    entry = line.strip()
    if not entry or entry.startswith("#"):
        continue

    entry = entry.removeprefix("||").removesuffix("^").strip("/")
    if domain_pattern.fullmatch(entry):
        domains.add(entry.lower())

# Check domains concurrently. Any HTTP response counts as responsive.
def check_domain(domain):
    request = urllib.request.Request(
        f"https://{domain}/",
        method="HEAD",
        headers={"User-Agent": "adblock-list-check/1.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=5):
            return domain
    except urllib.error.HTTPError:
        # An HTTP response, including 403 or 404, means the server responded.
        return domain
    except Exception:
        return None

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_domain, domains)
    active_domains = {domain for domain in results if domain is not None}

with open("filters.txt", "w", encoding="utf-8") as output:
    for domain in sorted(active_domains):
        output.write(f"||{domain}^\n")

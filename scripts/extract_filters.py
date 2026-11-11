import base64
import re
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urlsplit

BLOCKLIST_URL = (
    "https://codeberg.org/jcoscia/evasive-ads-blocklist/raw/branch/main/adcash.txt"
)

def fetch_text(url):
    request = urllib.request.Request(
        url,
        headers={"User-Agent": "adblock-list-updater/1.0"},
    )
    with urllib.request.urlopen(request, timeout=20) as response:
        return response.read().decode("utf-8")

# Extract Base64 values from the page's v array.
with open("page.html", encoding="utf-8") as file:
    page_source = file.read()

match = re.search(r"\bv\s*=\s*\[([^\]]*)\]", page_source)
if not match:
    raise SystemExit("Could not find the v array in page.html")

domains = set()

for value in re.findall(r'"([A-Za-z0-9+/=]+)"', match.group(1)):
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise SystemExit(f"Could not decode a v value: {error}")

    host = urlsplit("//" + decoded).hostname
    if not host:
        raise SystemExit(f"Could not extract a hostname from {decoded!r}")

    domains.add(host.lower())

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
        headers={"User-Agent": "Mozilla/8.0"},
    )

    try:
        with urllib.request.urlopen(request, timeout=5):
            return domain
    except urllib.error.HTTPError:
        return domain
    except Exception:
        return None

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_domain, domains)
    active_domains = {domain for domain in results if domain is not None}

with open("filters.txt", "w", encoding="utf-8") as output:
    for domain in sorted(active_domains):
        output.write(f"||{domain}^\n")

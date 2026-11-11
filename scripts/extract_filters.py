import base64
import re
import urllib.error
import urllib.request
from urllib.parse import urlsplit

source = open("page.html", encoding="utf-8").read()

match = re.search(r'\bv\s*=\s*\[([^\]]*)\]', source)
if not match:
    raise SystemExit("Could not find the v array")

encoded_values = re.findall(r'"([A-Za-z0-9+/=]+)"', match.group(1))

domains = set()
for value in encoded_values:
    decoded = base64.b64decode(value, validate=True).decode("utf-8")
    # The decoded values appear to be host/path strings, without a scheme.
    host = urlsplit("//" + decoded).hostname
    if not host:
        raise ValueError(f"Could not extract a hostname from {decoded!r}")
    domains.add(host.lower())

statuses = {}

for domain in sorted(domains):
    request = urllib.request.Request(
        f"https://{domain}/",
        method="HEAD",
        headers={"User-Agent": "adblock-list-check/1.0"},
    )
    try:
        with urllib.request.urlopen(request, timeout=8) as response:
            statuses[domain] = str(response.status)
    except urllib.error.HTTPError as error:
        # An HTTP error still means the domain responded.
        statuses[domain] = str(error.code)
    except Exception:
        statuses[domain] = "no response"

with open("domain-status.txt", "w", encoding="utf-8") as output:
    for domain, status in sorted(statuses.items()):
        output.write(f"{domain} {status}\n")


with open("filters.txt", "w", encoding="utf-8") as output:
    for domain in sorted(domains):
        output.write(f"||{domain}^\n")

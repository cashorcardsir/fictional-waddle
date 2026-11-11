import base64
import re
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

with open("filters.txt", "w", encoding="utf-8") as output:
    for domain in sorted(domains):
        output.write(f"||{domain}^\n")

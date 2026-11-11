import base64
import re
import time
import urllib.error
import urllib.request
from urllib.parse import urlsplit

with open("page.html", encoding="utf-8") as file:
    source = file.read()

match = re.search(r"\bv\s*=\s*\[([^\]]*)\]", source)
if not match:
    raise SystemExit("Could not find the v array in page.html")

encoded_values = re.findall(r'"([A-Za-z0-9+/=]+)"', match.group(1))

domains = set()
for value in encoded_values:
    try:
        decoded = base64.b64decode(value, validate=True).decode("utf-8")
    except (ValueError, UnicodeDecodeError) as error:
        raise SystemExit(f"Could not decode a v value: {error}")

    host = urlsplit("//" + decoded).hostname
    if not host:
        raise SystemExit(f"Could not extract a hostname from {decoded!r}")

    domains.add(host.lower())

active_domains = set()

for domain in domains:
    request = urllib.request.Request(
        f"https://{domain}/",
        method="HEAD",
        headers={"User-Agent": "curl"},
    )

    for attempt in range(2):
        try:
            with urllib.request.urlopen(request, timeout=8):
                active_domains.add(domain)
            break
        except urllib.error.HTTPError:
            # Any HTTP response, including 403 or 404, means the server responded.
            active_domains.add(domain)
            break
        except Exception:
            if attempt == 0:
                time.sleep(1)

with open("filters.txt", "w", encoding="utf-8") as output:
    for domain in sorted(active_domains):
        output.write(f"||{domain}^\n")

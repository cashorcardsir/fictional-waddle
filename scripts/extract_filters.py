import base64
import json
import re
import time
import urllib.error
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

import dns.exception
import dns.rdatatype
import dns.resolver

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

DNS_META_TYPES = {
    "ANY",
    "AXFR",
    "IXFR",
    "MAILA",
    "MAILB",
    "OPT",
    "TKEY",
    "TSIG",
}


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


def normalize_domain(value):
    """Normalize a domain and remove a leading www. label."""
    if not isinstance(value, str):
        return None

    domain = value.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    if DOMAIN_PATTERN.fullmatch(domain):
        return domain

    return None


def load_existing_targets(path):
    """Load old non-manual domain entries, skipping the marked manual section."""
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
                domain = normalize_domain(entry)
                if domain:
                    targets.add(domain)
    except FileNotFoundError:
        pass

    return targets


def load_add_domains(path):
    """Load and normalize plain-text domains, one per line."""
    domains = set()

    try:
        with open(path, encoding="utf-8") as source:
            for line in source:
                domain = normalize_domain(line)
                if domain:
                    domains.add(domain)
    except FileNotFoundError:
        pass

    return domains


def get_dns_record_types():
    """Get ordinary DNS record types supported by dnspython."""
    record_types = set()

    for name, value in dns.rdatatype.RdataType.__members__.items():
        if name in DNS_META_TYPES:
            continue

        code = int(value)
        if not 0 < code < 65535:
            continue

        record_type = dns.rdatatype.to_text(code)
        if not record_type.startswith("TYPE"):
            record_types.add(record_type)

    return sorted(record_types)


DNS_RECORD_TYPES = get_dns_record_types()


def has_dns_record(domain):
    """Return True if a DNS query finds a supported record type."""
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2.0
    resolver.lifetime = 2.5

    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(
                domain,
                record_type,
                search=False,
                lifetime=2.5,
            )
            if answer.rrset and len(answer.rrset) > 0:
                return True
        except (dns.exception.DNSException, OSError):
            continue
        except Exception:
            continue

    return False


def check_manual_domain(domain):
    """Return a manually listed domain only if DNS finds a record."""
    return domain if has_dns_record(domain) else None


def extract_domains_from_text(text):
    """Extract normalized domains from lines containing a domain or URL."""
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

        domain = normalize_domain(parsed.hostname)
        if domain:
            domains.add(domain)

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
            domain = normalize_domain(host)
            if domain:
                domains.add(domain)

    return domains


def extract_blocklist_domains(text):
    domains = set()

    for line in text.splitlines():
        entry = line.strip()
        if not entry or entry.startswith("#"):
            continue

        entry = entry.removeprefix("||").removesuffix("^").strip("/")
        domain = normalize_domain(entry)
        if domain:
            domains.add(domain)

    return domains


# Load previously discovered domains, excluding entries in the manual section.
# Invalid entries, including old IP addresses, are ignored.
targets = load_existing_targets(FILTERS_FILE)

# Fetch and decode the XOR-encoded JavaScript config.
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

            # Only collect domain fields; decoyDomainZones IPs are ignored.
            for field in ("adserverDomain", "decoyDomain", "cdnDomain"):
                domain = normalize_domain(config.get(field))
                if domain:
                    targets.add(domain)

        except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
            pass

# Get Base64-encoded hostnames from the stream page.
stream_source = fetch_text(STREAM_URL)
if stream_source:
    try:
        targets.update(extract_stream_domains(stream_source))
    except Exception:
        pass

# Add domains from tsd.txt and tsd_m.txt.
try:
    targets.update(fetch_tsd_domains())
except Exception:
    pass

# Add domains from the blocklist.
blocklist_text = fetch_text(BLOCKLIST_URL)
if blocklist_text:
    targets.update(extract_blocklist_domains(blocklist_text))

# Include only manually listed domains that resolve in DNS.
manual_candidates = load_add_domains(ADD_DOMAINS_FILE)
with ThreadPoolExecutor(max_workers=10) as executor:
    manual_results = executor.map(
        check_manual_domain,
        sorted(manual_candidates),
    )
    manual_targets = {
        domain for domain in manual_results if domain is not None
    }

targets.update(manual_targets)

if not targets:
    raise SystemExit("No targets were fetched; leaving filters.txt unchanged")


def check_target(target):
    """Return a domain if its HTTP or HTTPS server responds."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}/"

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


# Manual domains already passed their DNS check, so don't HTTP-check them.
targets_to_check = targets - manual_targets

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, sorted(targets_to_check))
    active_targets = {domain for domain in results if domain is not None}

active_targets.update(manual_targets)

with open(FILTERS_FILE, "w", encoding="utf-8") as output:
    # Write automatically sourced, responding domains outside the manual block.
    for domain in sorted(active_targets - manual_targets):
        output.write(f"||{domain}^\n")

    # Refresh this section from add-domains.txt after DNS checking.
    output.write(f"{MANUAL_START}\n")
    for domain in sorted(manual_targets):
        output.write(f"||{domain}^\n")
    output.write(f"{MANUAL_END}\n")

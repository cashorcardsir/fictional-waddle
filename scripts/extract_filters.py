import base64
import json
import re
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import urljoin, urlsplit

import dns.exception
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

# ANY is intentionally omitted: it is not a dependable way to discover records.
DNS_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
    "HTTPS",
    "SVCB",
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


def normalize_domain(value):
    """Normalize a domain, strip a leading www., and reject bare TLDs."""
    if not isinstance(value, str):
        return None

    domain = value.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    # Reject single-label names like "mt" so TLDs are not treated as domains.
    if "." not in domain:
        return None

    # Reject obviously malformed entries, including illegal characters.
    if not re.fullmatch(r"[a-z0-9.-]+", domain):
        return None

    # Reject labels that start/end with '-' or are empty.
    labels = domain.split(".")
    if any(not label or label.startswith("-") or label.endswith("-") for label in labels):
        return None

    if DOMAIN_PATTERN.fullmatch(domain):
        return domain

    return None


def load_existing_targets(path):
    """Load prior automatic entries, skipping the marked manual section."""
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


def check_dns_records(domain):
    """
    Return True if a supported DNS record is found, False if none exists,
    or None if DNS errors prevent a reliable determination.
    """
    resolver = dns.resolver.Resolver()
    resolver.timeout = 2
    resolver.lifetime = 3
    had_dns_error = False

    for record_type in DNS_RECORD_TYPES:
        try:
            answer = resolver.resolve(
                domain,
                record_type,
                search=False,
                lifetime=3,
                raise_on_no_answer=False,
            )
            if answer.rrset is not None and len(answer.rrset) > 0:
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            had_dns_error = True
        except dns.exception.DNSException:
            had_dns_error = True

    return None if had_dns_error else False


def clean_manual_domains(path):
    """
    Remove confirmed inactive entries from add-domains.txt.
    Preserve comments and entries with temporary DNS errors; return only
    manual domains confirmed to have a DNS record.
    """
    try:
        with open(path, "r", encoding="utf-8") as source:
            lines = source.readlines()
    except FileNotFoundError:
        return set()

    kept_lines = []
    active_domains = set()

    for raw_line in lines:
        newline = "\n" if raw_line.endswith("\n") else ""
        line_body = raw_line.rstrip("\r\n")

        # Keep blank lines and standalone comments unchanged.
        if not line_body.strip() or line_body.lstrip().startswith("#"):
            kept_lines.append(raw_line)
            continue

        # Ignore inline comments when checking the domain, but retain them
        # unless that domain is confirmed inactive.
        if "#" in line_body:
            entry_text, comment_text = line_body.split("#", 1)
            entry_text = entry_text.strip()
            comment_suffix = f" #{comment_text}" if comment_text else ""
        else:
            entry_text = line_body.strip()
            comment_suffix = ""

        if not entry_text:
            kept_lines.append(raw_line)
            continue

        domain = normalize_domain(entry_text)
        if domain is None:
            print(f"Removing malformed manual domain: {entry_text}")
            continue

        status = check_dns_records(domain)

        if status is False:
            print(f"Removing inactive manual domain: {domain}")
            continue

        kept_lines.append(f"{domain}{comment_suffix}{newline}")

        if status is True:
            active_domains.add(domain)

    with open(path, "w", encoding="utf-8") as output:
        output.writelines(kept_lines)

    return active_domains


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
    """Extract Base64-encoded hostnames from JavaScript array assignments."""
    domains = set()

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
    """Extract and normalize plain or adblock-style domain entries."""
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


# Check manual domains using DNS and remove confirmed inactive entries
# from add-domains.txt.
manual_targets = clean_manual_domains(ADD_DOMAINS_FILE)

# Load prior automatic entries, excluding the marked manual section.
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

            # Collect domain fields only; ignore decoyDomainZones IP addresses.
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

# DNS-check every automatically sourced target. Manual domains have already
# been DNS-checked, so they are excluded from this pass.
automatic_candidates = sorted(targets - manual_targets)

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_dns_records, automatic_candidates)

active_automatic_targets = {
    domain
    for domain, is_active in zip(automatic_candidates, results)
    if is_active is True
}

with open(FILTERS_FILE, "w", encoding="utf-8") as output:
    for domain in sorted(active_automatic_targets):
        output.write(f"||{domain}^\n")

    output.write(f"{MANUAL_START}\n")
    for domain in sorted(manual_targets):
        output.write(f"||{domain}^\n")
    output.write(f"{MANUAL_END}\n")

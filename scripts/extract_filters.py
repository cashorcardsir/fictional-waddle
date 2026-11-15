import base64
import json
import re
import time
import urllib.error
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

DNS_RECORD_TYPES = (
    "A",
    "AAAA",
    "CNAME",
    "MX",
    "NS",
    "TXT",
    "SOA",
    "CAA",
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
    """Normalize a domain and strip a leading www. label."""
    if not isinstance(value, str):
        return None

    domain = value.strip().lower().rstrip(".")
    if domain.startswith("www."):
        domain = domain[4:]

    if DOMAIN_PATTERN.fullmatch(domain):
        return domain

    return None


def load_existing_targets(path):
    """Load old automatic entries, skipping the marked manual section."""
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


def check_manual_domain(domain):
    """Return True if DNS finds any supported record, False if it does not, else None on DNS errors."""
    for record_type in DNS_RECORD_TYPES:
        try:
            answer = dns.resolver.resolve(
                domain,
                record_type,
                lifetime=5,
                raise_on_no_answer=False,
            )
            if answer and len(answer) > 0:
                return True
        except dns.resolver.NXDOMAIN:
            return False
        except dns.resolver.NoAnswer:
            continue
        except (dns.resolver.NoNameservers, dns.exception.Timeout):
            return None
        except dns.exception.DNSException:
            return None

    return False


def clean_manual_domains(path):
    """
    Remove inactive manual domains from add-domains.txt, ignore/keep comments,
    normalize domains, and return only DNS-active manual domains.
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

        if not line_body.strip():
            kept_lines.append(raw_line)
            continue

        # Ignore comments and preserve them in file if they are standalone
        if line_body.lstrip().startswith("#"):
            kept_lines.append(raw_line)
            continue

        # Split inline comments while preserving the comment text
        if "#" in line_body:
            entry_part, comment_part = line_body.split("#", 1)
            comment_text = comment_part.strip()
            entry_text = entry_part.strip()
            comment_suffix = f" # {comment_text}" if comment_text else ""
        else:
            entry_text = line_body.strip()
            comment_text = ""
            comment_suffix = ""

        if not entry_text:
            kept_lines.append(raw_line)
            continue

        normalized = normalize_domain(entry_text)
        if not normalized:
            kept_lines.append(raw_line)
            continue

        status = check_manual_domain(normalized)

        if status is False:
            print(f"Removing inactive manual domain: {normalized}")
            continue

        # Keep active and temporarily-unavailable manual domains.
        rewritten = f"{normalized}{comment_suffix}"
        kept_lines.append(rewritten + newline)

        if status is True:
            active_domains.add(normalized)

    with open(path, "w", encoding="utf-8") as output:
        output.writelines(kept_lines)

    return active_domains


def extract_domains_from_text(text):
    """Extract normalized domains from a text blob containing domains or URLs."""
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


# Manual entries are sanitized first: inactive ones are removed from add-domains.txt.
manual_targets = clean_manual_domains(ADD_DOMAINS_FILE)

# Keep previously discovered automatic targets, excluding the manual marker section.
targets = load_existing_targets(FILTERS_FILE)

# Add the active manual domains to the target set.
targets.update(manual_targets)

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

            # Only collect valid domain fields from the fetched config.
            for field in ("adserverDomain", "decoyDomain", "cdnDomain"):
                value = config.get(field)
                domain = normalize_domain(value)
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

# Add domains from tsd.txt and tsd_m.txt beside SOURCE_URL.
try:
    targets.update(fetch_tsd_domains())
except Exception:
    pass

# Add domains from the Codeberg blocklist.
blocklist_text = fetch_text(BLOCKLIST_URL)
if blocklist_text:
    targets.update(extract_blocklist_domains(blocklist_text))

if not targets:
    raise SystemExit("No targets were fetched; leaving filters.txt unchanged")


def check_target(target):
    """Return a domain if it responds to an HTTP/HTTPS request."""
    for scheme in ("https", "http"):
        url = f"{scheme}://{target}/"

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
                return target
            except Exception:
                continue

    return None


# Manual domains are already DNS-validated and should not be HTTP-checked again.
targets_to_check = targets - manual_targets

with ThreadPoolExecutor(max_workers=20) as executor:
    results = executor.map(check_target, sorted(targets_to_check))
    active_targets = {target for target in results if target is not None}

# Keep the manual domains that passed DNS validation.
active_targets.update(manual_targets)

with open(FILTERS_FILE, "w", encoding="utf-8") as output:
    # Write automatic entries outside the manual block.
    for target in sorted(active_targets - manual_targets):
        output.write(f"||{target}^\n")

    # Rebuild the manual marker section from the active manual entries.
    output.write(f"{MANUAL_START}\n")
    for target in sorted(manual_targets):
        output.write(f"||{target}^\n")
    output.write(f"{MANUAL_END}\n")

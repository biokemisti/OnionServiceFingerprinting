import gzip
import json
import re
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit


HERE = Path(__file__).resolve().parent
DATA_FILE = HERE / ""
TECHNOLOGY_DIR = HERE.parent / ""
REPORT_FILE = HERE / ""


def load_server_signatures() -> dict[str, re.Pattern[str]]:
    technologies = {}
    for path in sorted(TECHNOLOGY_DIR.glob("*.json")):
        technologies.update(json.loads(path.read_text(encoding="utf-8")))

    signatures = {}
    for name, technology in technologies.items():
        for header, pattern in technology.get("headers", {}).items():
            if header.casefold() == "server":
                # Drop version metadata, matching the general analyzer's convention.
                pattern = pattern.split(r"\;", 1)[0]
                signatures[name] = re.compile(pattern, re.IGNORECASE)
                break

    return signatures


def site_key(record: dict, record_number: int) -> str:
    url = record.get("url") or record.get("resolved_url")
    if not url:
        return f"<record {record_number}>"

    url = str(url)
    parsed = urlsplit(url if "://" in url else f"//{url}")
    return (parsed.hostname or url).casefold()


def server_header_values(headers: dict) -> list[str]:
    values = []
    for name, value in headers.items():
        if name.casefold() != "server":
            continue
        if isinstance(value, (list, tuple)):
            values.extend(str(item) for item in value if item is not None)
        elif value is not None:
            values.append(str(value))
    return [value for value in values if value.strip()]


def main() -> None:
    signatures = load_server_signatures()

    sites_with_response = set()
    sites_with_server_header = set()
    matched_sites = {name: set() for name in signatures}
    status_counts = Counter()
    record_count = 0
    response_record_count = 0

    with gzip.open(DATA_FILE, "rt", encoding="utf-8") as source:
        for record_count, line in enumerate(source, start=1):
            record = json.loads(line)
            site = site_key(record, record_count)

            status = record.get("status")
            if status is None:
                continue

            response_record_count += 1
            sites_with_response.add(site)
            if isinstance(status, int):
                status_counts[status] += 1

            values = server_header_values(record.get("headers") or {})
            if not values:
                continue

            sites_with_server_header.add(site)
            for name, pattern in signatures.items():
                if any(pattern.search(value) for value in values):
                    matched_sites[name].add(site)

    lines = [
        "Web server technology statistics",
        f"Input: {DATA_FILE.name}",
        "",
        f"Records scanned: {record_count:,}",
        f"Records with an HTTP response: {response_record_count:,}",
        f"Records without an HTTP response (excluded): {record_count - response_record_count:,}",
        f"Unique sites with an HTTP response: {len(sites_with_response):,}",
        f"Unique sites with a non-empty Server header: {len(sites_with_server_header):,}",
        "",
        "HTTP status codes (record counts):",
    ]

    if status_counts:
        lines.extend(
            f"  {status}: {count:,}"
            for status, count in sorted(status_counts.items())
        )
    else:
        lines.append("  None")

    lines.extend(["", "Detected technologies (unique sites):"])
    results = [
        (name, matched)
        for name, matched in matched_sites.items()
        if matched
    ]
    results.sort(key=lambda item: (-len(item[1]), item[0].casefold()))

    if results:
        denominator = len(sites_with_response) or 1
        for name, matched in results:
            percent = len(matched) / denominator * 100
            lines.append(
                f"  {name}: {len(matched):,} "
                f"({percent:.1f}% of responsive sites)"
            )
    else:
        lines.append("  None")

    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"Wrote {REPORT_FILE}")


if __name__ == "__main__":
    main()
    
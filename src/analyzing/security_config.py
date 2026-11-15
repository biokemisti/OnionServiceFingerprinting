import gzip
import json
import re
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt

from webserver import site_key


HERE = Path(__file__).resolve().parent
DATE = ""
DATA_FILE = HERE / f"{DATE}.jsonl.gz"
REPORT_FILE = HERE / f"security_config_stats_{DATE}.txt"
CHART_FILE = HERE / f"security_config_stats_{DATE}.png"

SECURITY_HEADERS = (
    ("Strict-Transport-Security (HSTS)", "strict-transport-security"),
    ("Content-Security-Policy (CSP)", "content-security-policy"),
    ("X-Frame-Options", "x-frame-options"),
    ("X-Content-Type-Options", "x-content-type-options"),
    ("Referrer-Policy", "referrer-policy"),
    ("Permissions-Policy", "permissions-policy"),
)
DISCLOSURE_HEADERS = (("Server", "server"), ("X-Powered-By", "x-powered-by"))
COOKIE_ATTRIBUTES = {
    "Secure": re.compile(r"(?:^|;)\s*secure\s*(?=;|,|$)", re.IGNORECASE),
    "HttpOnly": re.compile(r"(?:^|;)\s*httponly\s*(?=;|,|$)", re.IGNORECASE),
    "SameSite": re.compile(
        r"(?:^|;)\s*samesite\s*=",
        re.IGNORECASE,
    ),
}
CATEGORY_COLORS = {
    "Security response headers": "#3973ac",
    "Cookie attributes": "#43936c",
    "Technology disclosure": "#d27a34",
}


def header_values(headers: dict, header_name: str) -> list[str]:
    values = []
    for name, value in headers.items():
        if name.casefold() != header_name:
            continue
        if isinstance(value, (list, tuple)):
            values.extend(str(item) for item in value if item is not None)
        elif value is not None:
            values.append(str(value))
    return [value for value in values if value.strip()]


def analyze_records(records):
    sites_with_response = set()
    observed_sites = defaultdict(set)

    for record_number, record in enumerate(records, start=1):
        if record.get("status") is None:
            continue

        site = site_key(record, record_number)
        sites_with_response.add(site)
        headers = record.get("headers") or {}

        for label, name in SECURITY_HEADERS:
            if header_values(headers, name):
                observed_sites[label].add(site)

        for label, name in DISCLOSURE_HEADERS:
            if header_values(headers, name):
                observed_sites[label].add(site)

        cookies = header_values(headers, "set-cookie")
        if cookies:
            observed_sites["Set-Cookie present"].add(site)
            for label, pattern in COOKIE_ATTRIBUTES.items():
                if any(pattern.search(cookie) for cookie in cookies):
                    observed_sites[f"Cookie {label}"].add(site)

    return sites_with_response, observed_sites


def report_metrics(sites_with_response, observed_sites):
    metrics = [
        ("Security response headers", label, observed_sites[label])
        for label, _ in SECURITY_HEADERS
    ]
    metrics.extend(
        ("Cookie attributes", label, observed_sites[label])
        for label in (
            "Set-Cookie present",
            "Cookie Secure",
            "Cookie HttpOnly",
            "Cookie SameSite",
        )
    )
    metrics.extend(
        ("Technology disclosure", label, observed_sites[label])
        for label, _ in DISCLOSURE_HEADERS
    )
    denominator = len(sites_with_response)
    return [
        (category, label, len(sites), len(sites) / denominator * 100 if denominator else 0)
        for category, label, sites in metrics
    ]


def write_report(metrics, denominator):
    lines = [
        "Security and response-configuration indicators",
        f"Input: {DATA_FILE.name}",
        f"Unique sites with an HTTP response: {denominator:,}",
        "",
        "Counts are unique sites. Indicators may overlap; cookie attributes mean at least "
        "one Set-Cookie value had that attribute.",
        "",
    ]
    current_category = None
    for category, label, count, percentage in metrics:
        if category != current_category:
            if current_category is not None:
                lines.append("")
            lines.append(f"{category}:")
            current_category = category
        lines.append(f"  {label}: {count:,} ({percentage:.1f}%)")
    REPORT_FILE.write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_chart(metrics, denominator):
    fig, ax = plt.subplots(figsize=(12, 8))
    rows = []
    for category in CATEGORY_COLORS:
        rows.append((category, None, 0, 0))
        rows.extend(metric for metric in metrics if metric[0] == category)

    for position, (category, label, count, percentage) in enumerate(rows):
        if label is None:
            continue
        ax.barh(
            position,
            percentage,
            color=CATEGORY_COLORS[category],
            height=0.68,
            zorder=3,
        )
        ax.text(
            min(percentage + 0.8, 103),
            position,
            f"{count:,} sites  |  {percentage:.1f}%",
            va="center",
            ha="left",
            fontsize=9,
            color="#252525",
        )

    ax.set_yticks(
        range(len(rows)),
        [label if label is not None else category for category, label, _, _ in rows],
    )
    ax.invert_yaxis()
    for tick, (category, label, _, _) in zip(ax.get_yticklabels(), rows):
        tick.set_color(CATEGORY_COLORS[category])
        if label is None:
            tick.set_fontweight("bold")
            tick.set_fontsize(10)

    ax.set_xlim(0, 120)
    ax.set_xticks(range(0, 101, 10), [f"{value}%" for value in range(0, 101, 10)])
    ax.set_xlabel("Percentage of responsive sites")
    ax.set_title(
        f"Security and response-configuration indicators ({DATE})\n"
        f"Unique sites with an HTTP response: n = {denominator:,}",
        loc="left",
        fontsize=15,
        fontweight="bold",
        pad=18,
    )
    ax.xaxis.grid(True, color="#d9d9d9", linewidth=0.8, zorder=0)
    ax.set_axisbelow(True)
    ax.spines[["top", "right", "left"]].set_visible(False)
    ax.tick_params(axis="y", length=0, pad=9)
    ax.tick_params(axis="x", colors="#555555")
    fig.text(
        0.12,
        0.025,
        "Presence indicates a header or cookie attribute was observed; it does not "
        "assess the quality of its configuration.",
        fontsize=9,
        color="#555555",
    )
    fig.tight_layout(rect=(0.08, 0.06, 0.98, 0.97))
    fig.savefig(CHART_FILE, dpi=200, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    with gzip.open(DATA_FILE, "rt", encoding="utf-8") as source:
        records = (json.loads(line) for line in source)
        sites, observed = analyze_records(records)

    metrics = report_metrics(sites, observed)
    write_report(metrics, len(sites))
    write_chart(metrics, len(sites))
    print(f"Wrote {REPORT_FILE}")
    print(f"Wrote {CHART_FILE}")


if __name__ == "__main__":
    main()

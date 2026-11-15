import gzip
import json
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt
from bs4 import BeautifulSoup

from webserver import site_key


HERE = Path(__file__).resolve().parent
DATE = ""
DATA_FILE = HERE / f"{DATE}.jsonl.gz"
REPORT_FILE = HERE / f"indicator_coverage_{DATE}.txt"
CHART_FILE = HERE / f"indicator_coverage_{DATE}.png"

INDICATORS = (
    (
        "HTTP response",
        (
            "HTTP status",
            "Any response header",
            "Content-Type",
            "Server",
            "X-Powered-By",
            "Last-Modified",
            "ETag",
            "Set-Cookie",
            "Onion-Location",
        ),
    ),
    (
        "Page content and metadata",
        (
            "Non-empty HTML body",
            "Page title",
            "At least one meta tag",
            "Meta description",
            "Generator meta tag",
        ),
    ),
    (
        "Source and asset fingerprints",
        (
            "At least one script element",
            "Inline JavaScript",
            "External JavaScript file",
            "Stylesheet link",
            "Inline style",
        ),
    ),
)
CATEGORY_COLORS = {
    "HTTP response": "#3973ac",
    "Page content and metadata": "#43936c",
    "Source and asset fingerprints": "#d27a34",
}


def has_header(headers: dict, header_name: str) -> bool:
    return any(
        name.casefold() == header_name and value not in (None, "", [], {})
        for name, value in headers.items()
    )


def analyze_records(records):
    sites_with_response = set()
    indicator_sites = defaultdict(set)

    for record_number, record in enumerate(records, start=1):
        if record.get("status") is None:
            continue

        site = site_key(record, record_number)
        sites_with_response.add(site)
        headers = record.get("headers") or {}
        html = record.get("html") or ""

        indicator_sites["HTTP status"].add(site)
        if any(value not in (None, "", [], {}) for value in headers.values()):
            indicator_sites["Any response header"].add(site)
        for label, name in (
            ("Content-Type", "content-type"),
            ("Server", "server"),
            ("X-Powered-By", "x-powered-by"),
            ("Last-Modified", "last-modified"),
            ("ETag", "etag"),
            ("Set-Cookie", "set-cookie"),
            ("Onion-Location", "onion-location"),
        ):
            if has_header(headers, name):
                indicator_sites[label].add(site)

        if html.strip():
            indicator_sites["Non-empty HTML body"].add(site)
            soup = BeautifulSoup(html, "html.parser")
            if soup.title and soup.title.get_text(strip=True):
                indicator_sites["Page title"].add(site)

            meta_tags = soup.find_all("meta")
            if meta_tags:
                indicator_sites["At least one meta tag"].add(site)
            if any(
                tag.get("name", "").casefold() == "description"
                and tag.get("content", "").strip()
                for tag in meta_tags
            ):
                indicator_sites["Meta description"].add(site)
            if any(
                tag.get("name", "").casefold() == "generator"
                and tag.get("content", "").strip()
                for tag in meta_tags
            ):
                indicator_sites["Generator meta tag"].add(site)

            scripts = soup.find_all("script")
            if scripts:
                indicator_sites["At least one script element"].add(site)
            if any(not script.get("src") and script.get_text(strip=True) for script in scripts):
                indicator_sites["Inline JavaScript"].add(site)
            if record.get("js_files"):
                indicator_sites["External JavaScript file"].add(site)
            elif any(script.get("src") for script in scripts):
                indicator_sites["External JavaScript file"].add(site)

            if record.get("css_files") or soup.find("link", rel="stylesheet"):
                indicator_sites["Stylesheet link"].add(site)
            if any(style.get_text(strip=True) for style in soup.find_all("style")):
                indicator_sites["Inline style"].add(site)

    return sites_with_response, indicator_sites


def report_metrics(sites_with_response, indicator_sites):
    denominator = len(sites_with_response)
    return [
        (
            category,
            label,
            len(indicator_sites[label]),
            len(indicator_sites[label]) / denominator * 100 if denominator else 0,
        )
        for category, labels in INDICATORS
        for label in labels
    ]


def write_report(metrics, denominator):
    lines = [
        "Available technical indicators from HTTP GET responses",
        f"Input: {DATA_FILE.name}",
        f"Unique sites with an HTTP response: {denominator:,}",
        "",
        "Counts are unique sites. Indicators are not mutually exclusive and show "
        "whether information was present, not whether it revealed a specific technology.",
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
    rows = []
    for category, labels in INDICATORS:
        rows.append((category, None, 0, 0))
        rows.extend(metric for metric in metrics if metric[0] == category)

    fig, ax = plt.subplots(figsize=(12, 10))
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
            min(percentage + 0.8, 102),
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
        f"Technical information available from HTTP GET ({DATE})\n"
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
        "Presence shows that a signal was collected; it does not mean every signal "
        "identifies a technology or reveals its configuration.",
        fontsize=9,
        color="#555555",
    )
    fig.tight_layout(rect=(0.08, 0.06, 0.98, 0.97))
    fig.savefig(CHART_FILE, dpi=200, bbox_inches="tight")
    plt.close(fig)


def main() -> None:
    with gzip.open(DATA_FILE, "rt", encoding="utf-8") as source:
        records = (json.loads(line) for line in source)
        sites, indicators = analyze_records(records)

    metrics = report_metrics(sites, indicators)
    write_report(metrics, len(sites))
    write_chart(metrics, len(sites))
    print(f"Wrote {REPORT_FILE}")
    print(f"Wrote {CHART_FILE}")


if __name__ == "__main__":
    main()

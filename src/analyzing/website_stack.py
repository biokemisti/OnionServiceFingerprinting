import gzip
import json
import os
import sys
from collections import defaultdict
from concurrent.futures import ProcessPoolExecutor
from pathlib import Path

from general_analyzer import matches, prepare_page, technologies
from webserver import site_key


HERE = Path(__file__).resolve().parent
DATA_FILE = HERE / ""
REPORT_FILE = HERE / ""

# Avoid testing unrelated catalog entries such as plugins and peripheral libraries.
BUILDER_NAMES = {
    "B12",
    "BigCommerce",
    "Blogger",
    "Bubble",
    "Carrd",
    "Cargo",
    "Craft CMS",
    "Durable",
    "Drupal",
    "Duda",
    "Elementor",
    "Framer Sites",
    "Ghost",
    "Hostinger Website Builder",
    "Joomla",
    "Magento",
    "Mobirise",
    "Nicepage",
    "Pagecloud",
    "PrestaShop",
    "RapidWeaver",
    "Shopify",
    "SiteOrigin Page Builder",
    "Squarespace",
    "Themify Builder",
    "TYPO3",
    "Weebly",
    "Webflow",
    "Webstudio",
    "Wix",
    "WordPress",
    "WordPress Block Editor",
    "WordPress Site Editor",
    "wpBakery",
    "Yola",
}
FRAMEWORK_NAMES = {
    "Alpine.js",
    "Angular",
    "AngularJS",
    "Astro",
    "Backbone.js",
    "Docusaurus",
    "Eleventy",
    "Ember.js",
    "Gatsby",
    "Hexo",
    "Hugo",
    "Jekyll",
    "Nuxt.js",
    "Next.js",
    "Pelican",
    "Preact",
    "Qwik",
    "React",
    "Remix",
    "Svelte",
    "SvelteKit",
    "Vue.js",
    "Zola",
}
_RELEVANT_TECHNOLOGIES = {}
PROGRESS_INTERVAL = 500


def technology_groups(name: str) -> tuple[str, ...]:
    groups = []
    if name in BUILDER_NAMES:
        groups.append("builders")
    if name in FRAMEWORK_NAMES:
        groups.append("frameworks")
    return tuple(groups)


def _initialize_worker(relevant):
    global _RELEVANT_TECHNOLOGIES
    _RELEVANT_TECHNOLOGIES = relevant


def _analyze_record(item):
    record_number, record = item
    page = prepare_page(record)
    matches_found = []
    for name, (technology, groups) in _RELEVANT_TECHNOLOGIES.items():
        if matches(technology, page):
            matches_found.append((name, groups))
    return site_key(record, record_number), matches_found


def _show_progress(response_record_count: int) -> None:
    if response_record_count and response_record_count % PROGRESS_INTERVAL == 0:
        print(
            f"Analyzed {response_record_count:,} responsive pages",
            file=sys.stderr,
            flush=True,
        )


def analyze_records(records, workers: int = 1):
    sites_with_response = set()
    detected_sites = {"builders": defaultdict(set), "frameworks": defaultdict(set)}
    total_records = 0
    response_record_count = 0
    relevant = {}
    for name, technology in technologies.items():
        groups = technology_groups(name)
        if groups:
            relevant[name] = (technology, groups)

    def responsive_records():
        nonlocal total_records
        for total_records, record in enumerate(records, start=1):
            if record.get("status") is not None:
                yield total_records, record

    if workers > 1:
        with ProcessPoolExecutor(
            max_workers=workers,
            initializer=_initialize_worker,
            initargs=(relevant,),
        ) as executor:
            results = executor.map(_analyze_record, responsive_records(), chunksize=64)
            for site, matches_found in results:
                response_record_count += 1
                sites_with_response.add(site)
                for name, groups in matches_found:
                    for group in groups:
                        detected_sites[group][name].add(site)
                _show_progress(response_record_count)
    else:
        _initialize_worker(relevant)
        for item in responsive_records():
            site, matches_found = _analyze_record(item)
            response_record_count += 1
            sites_with_response.add(site)
            for name, groups in matches_found:
                for group in groups:
                    detected_sites[group][name].add(site)
            _show_progress(response_record_count)

    return total_records, response_record_count, sites_with_response, detected_sites


def report_lines(record_count, response_record_count, sites_with_response, detected_sites):
    lines = [
        "Website builder and framework statistics",
        f"Input: {DATA_FILE.name}",
        "",
        f"Records scanned: {record_count:,}",
        f"Records with an HTTP response: {response_record_count:,}",
        f"Records without an HTTP response (excluded): {record_count - response_record_count:,}",
        f"Unique sites with an HTTP response: {len(sites_with_response):,}",
        "",
    ]

    for index, (group, heading) in enumerate(
        (
            ("builders", "Detected website builders and CMSs (unique sites):"),
            ("frameworks", "Detected frameworks and static site generators (unique sites):"),
        )
    ):
        if index:
            lines.append("")
        lines.append(heading)
        results = sorted(
            detected_sites[group].items(),
            key=lambda item: (-len(item[1]), item[0].casefold()),
        )
        if results:
            lines.extend(f"  {name}: {len(sites):,}" for name, sites in results)
        else:
            lines.append("  None")

    identified_sites = set().union(
        *(sites for group in detected_sites.values() for sites in group.values())
    )
    handmade_count = len(sites_with_response - identified_sites)
    lines.extend(
        [
            "",
            "No recognized builder or framework detected (unique sites):",
            f"  {handmade_count:,}",
        ]
    )
    return lines


def main() -> None:
    with gzip.open(DATA_FILE, "rt", encoding="utf-8") as source:
        records = (json.loads(line) for line in source)
        workers = min(8, os.cpu_count() or 1)
        stats = analyze_records(records, workers=workers)

    REPORT_FILE.write_text("\n".join(report_lines(*stats)) + "\n", encoding="utf-8")
    print(f"Wrote {REPORT_FILE}")


if __name__ == "__main__":
    main()

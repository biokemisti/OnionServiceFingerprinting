""" """

from pathlib import Path
from datetime import datetime, timezone
from bs4 import BeautifulSoup
from dataclasses import dataclass
import sys
import requests
import gzip
import json
import datetime
import time


@dataclass
class Config:
    SOCKS5_IP = "127.0.0.1"
    SOCKS5_PORT = 9050
    TOR_URLS_FILE = Path(__file__).resolve().parent / ""
    HTTP_PORT = 80


@dataclass
class Format:
    NEUTRAL = "[*]"
    GOOD = f"\033[92m[+]\x1b[0m"
    ATTENTION = "\033[93m[!]\x1b[0m"
    BAD = "\033[91m[-]\x1b[0m"


def default_get(
    url: str, session: requests.Session, timeout: int = 15
) -> requests.Response | None:
    """
    Sends a get request to the url usgin the requests library through
    a Tor proxy and returns the response. Uses Tor browser v16.0 user-agent.
    """

    url = "http://" + url

    proxies = {
        "http": f"socks5h://{Config.SOCKS5_IP}:{Config.SOCKS5_PORT}",
        "https": f"socks5h://{Config.SOCKS5_IP}:{Config.SOCKS5_PORT}",
    }

    headers = {
        "User-Agent": "Mozilla/5.0 (Windows NT 6.1; rv:24.0) Gecko/20100101 Firefox/24.0"
    }

    res = None
    try:
        print(f"[*] Sending default request to {url}. (Timeout={timeout}s)")
        res = session.get(
            url, proxies=proxies, headers=headers, timeout=timeout, allow_redirects=True
        )

    except Exception as e:
        print(f"Default request failed: {e}")
        return None

    return res


def extract_page_fields(html: str) -> dict:
    """ """
    soup = BeautifulSoup(html, "html.parser")

    description = soup.find("meta", attrs={"name": "description"})
    generator = soup.find("meta", attrs={"name": "generator"})

    return {
        "title": soup.title.string if soup.title else None,
        "meta_description": description.get("content") if description else None,
        "generator": generator.get("content") if generator else None,
        "css_files": [
            link["href"]
            for link in soup.find_all("link", rel="stylesheet")
            if link.get("href")
        ],
        "js_files": [
            script["src"]
            for script in soup.find_all("script", src=True)
            if script.get("src")
        ],
    }


def save_record(url, resolved_url, status, headers_dict, html_content, error_msg):
    try:
        html_str = (
            html_content.decode("utf-8", errors="ignore")
            if isinstance(html_content, bytes)
            else html_content
        )

        page_fields = extract_page_fields(html_str)

        record = {
            "url": url,
            "resolved_url": resolved_url,
            "title": page_fields.get("title", None),
            "meta_description": page_fields.get("meta_description", None),
            "generator": page_fields.get("generator", None),
            "timestamp": datetime.datetime.now(timezone.utc).isoformat(),
            "status": status,
            "headers": dict(headers_dict) if headers_dict else {},
            "css_files": page_fields.get("css_files", []),
            "js_files": page_fields.get("js_files", []),
            "html": html_str,
            "error": error_msg,
        }

        filepath = f"{datetime.date.today()}-1-2.jsonl.gz"

        with gzip.open(filepath, "at", encoding="utf-8") as file:
            file.write(json.dumps(record) + "\n")

        print(f"{Format.GOOD} Record for {url} saved successfully")

    except Exception as e:
        print(f"{Format.BAD} Failed to save record for {url}: {e}")


def main() -> int:
    try:
        with requests.Session() as session:
            with open(Config.TOR_URLS_FILE, "rt") as file:
                for url in file:
                    url = url.strip()

                    error_msg = None
                    resolved_url = None
                    default_status = None
                    default_headers = {}
                    default_html = b""

                    try:
                        default_response = default_get(url, session)
                        if default_response is not None:
                            resolved_url = default_response.url
                            default_status = default_response.status_code
                            default_headers = default_response.headers
                            default_html = default_response.content
                        else:
                            error_msg = f"Default GET returned None"

                    except Exception as e:
                        error_msg = f"Default GET error: {e}"

                    time.sleep(1)

                    save_record(
                        url,
                        resolved_url,
                        default_status,
                        default_headers,
                        default_html,
                        error_msg,
                    )

    except KeyboardInterrupt:
        print(f"{Format.ATTENTION} Scrape interrupted manually.")
        return 0

    except Exception as e:
        print(f"{Format.BAD} Critical error: {e}")
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

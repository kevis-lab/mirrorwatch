"""Candidate generation and safe HTTP probing."""

from __future__ import annotations

import asyncio
from urllib.parse import urljoin, urlparse

import aiohttp

from network import hostname_from_url, is_public_target


def normalise_url(value: str) -> str:
    value = value.strip()
    return value if value.startswith(("http://", "https://")) else f"https://{value}"


def generate_candidate_urls(reference_url: str, start: int, end: int, tlds: list[str], prefix: bool, suffix: bool) -> list[str]:
    original_host = hostname_from_url(reference_url)
    host = original_host.removeprefix("www.")
    labels = host.split(".")
    if len(labels) < 2:
        return []
    brand = labels[0]
    clean_brand = "".join(ch for ch in brand if not ch.isdigit()) or brand
    domains: set[str] = set()
    for tld in set(tlds):
        domains.add(f"{clean_brand}.{tld}")
        for number in range(start, end + 1):
            if prefix:
                domains.add(f"{number}{clean_brand}.{tld}")
            if suffix:
                domains.add(f"{clean_brand}{number}.{tld}")
    domains.discard(host)
    urls = {f"https://{domain}" for domain in domains} | {f"https://www.{domain}" for domain in domains}
    # The reference row represents the exact input URL. Probe its missing www/non-www
    # counterpart too, so both variants are always visible in the report.
    counterpart = host if original_host.startswith("www.") else f"www.{host}"
    urls.add(f"https://{counterpart}")
    return sorted(urls)


async def _request_chain(session: aiohttp.ClientSession, url: str) -> dict | None:
    chain: list[str] = []
    current = url
    for _ in range(6):
        is_public, host, ips = is_public_target(current)
        if not is_public:
            return None
        try:
            async with session.get(current, allow_redirects=False, timeout=aiohttp.ClientTimeout(total=10)) as response:
                chain.append(current)
                if response.status in {301, 302, 303, 307, 308} and response.headers.get("Location"):
                    current = urljoin(current, response.headers["Location"])
                    continue
                return {
                    "name": url,
                    "target": str(response.url),
                    "hostname": host,
                    "ips": ips,
                    "status": response.status,
                    "redirects": chain,
                }
        except (aiohttp.ClientError, asyncio.TimeoutError):
            return None
    return None


async def check_candidate_urls(urls: list[str], user_agent: str, stop_event, concurrency: int = 20) -> list[dict]:
    connector = aiohttp.TCPConnector(limit=concurrency)
    semaphore = asyncio.Semaphore(concurrency)
    async with aiohttp.ClientSession(headers={"User-Agent": user_agent}, connector=connector) as session:
        async def probe(url: str):
            if stop_event.is_set():
                return None
            async with semaphore:
                result = await _request_chain(session, url)
                # Some older domains answer only over HTTP. Keep their result rather
                # than silently treating the hostname as absent.
                if result is None and url.startswith("https://"):
                    return await _request_chain(session, "http://" + url.removeprefix("https://"))
                return result
        records = await asyncio.gather(*(probe(url) for url in urls))
    return [record for record in records if record]

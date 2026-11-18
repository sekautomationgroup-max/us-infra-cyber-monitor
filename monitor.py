#!/usr/bin/env python3
"""
U.S. Infrastructure & Cyber Threat Monitor, version 1.

One run (designed for GitHub Actions on a 5-minute cron):

  1. Pull every configured source (official feeds + news). Each source is
     retried 3 times; a failing source never stops the run.
  2. Keep items about U.S. infrastructure, cyber incidents, outages, and
     Iran news involving the United States.
  3. Tag verification: Confirmed / Corroborated / Unverified - Credible
     Source / Unverified - Unknown Source. Unverified items are kept.
  4. Assign severity (Critical / High / Moderate / Low) by source + keywords.
  5. Skip anything already in seen.json.
  6. Write every alert to alerts/recent.json (last 48 hours), which is
     committed to the repo. A scheduled Claude routine reads that file and
     notifies you. If Gmail secrets are configured, Critical + High also go
     out immediately by email and text and Moderate goes in a 6-hour digest.
  7. If the script itself crashes, the failure is emailed when email is
     configured; the routine also notices when recent.json goes stale.

Usage:
  python monitor.py                 normal run (sends if secrets are set)
  python monitor.py --dry-run       fetch + classify, print instead of send
  python monitor.py --force-digest  send the digest now regardless of timer
  python monitor.py --test-delivery send a test email + text to verify secrets
  python monitor.py --report-failure  used by the workflow's failure step
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import logging
import os
import re
import sys
import threading
import time
import traceback
from dataclasses import dataclass, field, asdict
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable
from urllib.parse import parse_qs, urlparse

import feedparser
import requests
from dateutil import parser as dateparser

import config as C
import notify

log = logging.getLogger("monitor")

UTC = timezone.utc
NOW = datetime.now(UTC)

SEV_CRITICAL, SEV_HIGH, SEV_MODERATE, SEV_LOW = "Critical", "High", "Moderate", "Low"
SEV_RANK = {SEV_CRITICAL: 4, SEV_HIGH: 3, SEV_MODERATE: 2, SEV_LOW: 1}

V_CONFIRMED = "Confirmed"
V_CORROBORATED = "Corroborated"
V_UNV_CREDIBLE = "Unverified - Credible Source"
V_UNV_UNKNOWN = "Unverified - Unknown Source"

STATE_FILE_DEFAULT = "seen.json"
ALERTS_FILE_DEFAULT = os.path.join("alerts", "recent.json")
ALERTS_RETENTION_HOURS = 48


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class Item:
    id: str
    source: str              # human name of the feed, e.g. "CISA KEV"
    domain: str              # originating domain, used for credibility
    title: str
    url: str
    summary: str = ""
    published: datetime | None = None
    start_time: datetime | None = None
    official: bool = False
    severity_hint: str | None = None   # source-specific override
    locations: list[str] = field(default_factory=list)
    organizations: list[str] = field(default_factory=list)
    cause: str = ""
    extra_links: list[str] = field(default_factory=list)
    # filled in by classification
    severity: str = SEV_MODERATE
    verification: str = V_UNV_UNKNOWN
    corroborators: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    is_news: bool = False    # participates in corroboration clustering

    @property
    def text(self) -> str:
        return f"{self.title}\n{self.summary}"

    @property
    def unverified(self) -> bool:
        return self.verification in (V_UNV_CREDIBLE, V_UNV_UNKNOWN)


# ---------------------------------------------------------------------------
# Small utilities
# ---------------------------------------------------------------------------

def _compile_terms(terms: Iterable[str]) -> re.Pattern:
    parts = []
    for t in terms:
        t = t.strip().lower()
        if not t:
            continue
        if t.endswith("*"):
            parts.append(r"(?<!\w)" + re.escape(t[:-1]) + r"\w*")
        else:
            parts.append(r"(?<!\w)" + re.escape(t) + r"(?!\w)")
    return re.compile("|".join(parts), re.IGNORECASE)


RX_INFRA = _compile_terms(C.INFRA_TERMS)
RX_CYBER = _compile_terms(C.CYBER_TERMS)
RX_OUTAGE = _compile_terms(C.OUTAGE_TERMS)
RX_IRAN = _compile_terms(C.IRAN_TERMS)
RX_US = _compile_terms(C.US_TERMS)
RX_CRITICAL = _compile_terms(C.CRITICAL_TERMS)
RX_HIGH = _compile_terms(C.HIGH_TERMS)
RX_RESTRICTED = _compile_terms(C.RESTRICTED_CAUSE_TERMS)
RX_AFTERMATH = _compile_terms(C.AFTERMATH_TERMS)
RX_STATES = re.compile(r"(?<!\w)(" + "|".join(re.escape(s) for s in C.STATES) + r")(?!\w)")
RX_STATE_ABBR = re.compile(r",\s*(" + "|".join(C.STATES.values()) + r")(?!\w)")
RX_CITIES = _compile_terms(C.US_CITIES)
RX_ORGS = _compile_terms(C.ORG_HINTS)
RX_TAGS = re.compile(r"<[^>]+>")
RX_WS = re.compile(r"\s+")
ABBR_TO_STATE = {v: k for k, v in C.STATES.items()}

STOPWORDS = set("""a an the and or but of to in on at for from by with as is are was were be been
being this that these those it its into over after before about amid among says said say
after new more than against will would could has have had who what when where why how not
their there they them his her him she he we you your our us""".split())


def clean_text(s: str | None) -> str:
    if not s:
        return ""
    s = html.unescape(RX_TAGS.sub(" ", s))
    return RX_WS.sub(" ", s).strip()


def truncate(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n - 1].rstrip() + "…"


def domain_of(url: str) -> str:
    try:
        host = urlparse(url).netloc.lower()
    except Exception:  # noqa: BLE001
        return ""
    host = host.split(":")[0]
    if host.startswith("www."):
        host = host[4:]
    return host


def base_domain(host: str) -> str:
    parts = host.split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "gov", "org", "net") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:]) if len(parts) >= 2 else host


def is_official_domain(host: str) -> bool:
    host = host.lower()
    if host.endswith(".gov") or host.endswith(".mil"):
        return True
    return base_domain(host) in C.OFFICIAL_DOMAINS or host in C.OFFICIAL_DOMAINS


def is_credible_domain(host: str) -> bool:
    return base_domain(host) in C.CREDIBLE_DOMAINS or host in C.CREDIBLE_DOMAINS


def to_dt(value) -> datetime | None:
    """Parse many timestamp shapes into aware UTC datetime. Date-only values
    are moved to the end of that day so same-day items are never aged out."""
    if value is None or value == "":
        return None
    try:
        if isinstance(value, (int, float)):
            ts = value / 1000 if value > 1e11 else value
            return datetime.fromtimestamp(ts, UTC)
        if isinstance(value, time.struct_time):
            return datetime(*value[:6], tzinfo=UTC)
        s = str(value).strip()
        date_only = re.fullmatch(r"\d{4}-\d{2}-\d{2}", s) is not None
        dt = dateparser.parse(s)
        if dt is None:
            return None
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=UTC)
        dt = dt.astimezone(UTC)
        if date_only:
            dt = dt.replace(hour=23, minute=59, second=59)
        return dt
    except Exception:  # noqa: BLE001
        return None


def fmt_dt(dt: datetime | None) -> str:
    if not dt:
        return "Not stated"
    dt = dt.astimezone(UTC)
    if (dt.hour, dt.minute, dt.second) == (23, 59, 59):
        return dt.strftime("%Y-%m-%d (date only)")
    return dt.strftime("%Y-%m-%d %H:%M UTC")


def stable_id(*parts: str) -> str:
    return hashlib.sha1("|".join(parts).encode("utf-8", "ignore")).hexdigest()[:16]


def title_tokens(title: str) -> set[str]:
    words = re.findall(r"[a-z0-9][a-z0-9'\-]+", title.lower())
    return {w for w in words if len(w) > 3 and w not in STOPWORDS}


# ---------------------------------------------------------------------------
# HTTP with retries
# ---------------------------------------------------------------------------

class SourceError(Exception):
    pass


_session = requests.Session()


def http_get(url: str, *, headers: dict | None = None, retries: int = C.HTTP_RETRIES) -> requests.Response:
    hdrs = {"User-Agent": C.USER_AGENT, "Accept": "*/*"}
    if headers:
        hdrs.update(headers)
    last: Exception | None = None
    for attempt in range(1, retries + 1):
        try:
            resp = _session.get(url, headers=hdrs, timeout=C.HTTP_TIMEOUT_SECONDS)
            if resp.status_code == 429:
                raise SourceError(f"HTTP 429 rate limited: {truncate(resp.text, 120)}")
            if resp.status_code >= 400:
                raise SourceError(f"HTTP {resp.status_code}")
            return resp
        except Exception as exc:  # noqa: BLE001
            last = exc
            wait = C.HTTP_RETRY_BACKOFF_SECONDS * attempt
            if "429" in str(exc):
                wait = max(wait, 6)
            log.warning("GET %s attempt %d/%d failed: %s", url[:90], attempt, retries, exc)
            if attempt < retries:
                time.sleep(wait)
    raise SourceError(f"{url[:90]} failed after {retries} attempts: {last}")


def http_json(url: str, **kw):
    return http_get(url, **kw).json()


def http_feed(url: str, **kw) -> feedparser.FeedParserDict:
    resp = http_get(url, **kw)
    parsed = feedparser.parse(resp.content)
    if parsed.bozo and not parsed.entries:
        raise SourceError(f"feed parse error: {parsed.bozo_exception}")
    return parsed


def http_feed_any(urls: list[str]) -> tuple[feedparser.FeedParserDict, str]:
    """Try each feed URL in order; return the first that parses, plus its URL."""
    errors = []
    for i, u in enumerate(urls):
        try:
            return http_feed(u, retries=2 if len(urls) > 1 else C.HTTP_RETRIES), u
        except SourceError as exc:
            errors.append(str(exc))
            if i + 1 < len(urls):
                log.warning("Feed refused, trying fallback %d/%d: %s", i + 2, len(urls), truncate(str(exc), 120))
    raise SourceError(" | ".join(errors))


def unwrap_aggregator_link(link: str) -> str:
    """Bing News wraps the article URL in ?url=... ; return the real article."""
    if "bing.com/news/apiclick" in link:
        q = parse_qs(urlparse(link).query)
        if q.get("url"):
            return q["url"][0]
    return link


def is_aggregator(feed_url: str) -> bool:
    return "news.google.com" in feed_url or "bing.com/news" in feed_url


def entry_domain(e, link: str, feed_url: str, default: str) -> str:
    """Real originating domain of a feed entry. Google News exposes it in
    <source href>; Bing links are unwrapped to the article URL."""
    src = e.get("source", {})
    if isinstance(src, dict) and src.get("href"):
        return domain_of(src["href"])
    if "news.google.com" in link:
        return default
    return domain_of(link) or default


def aggregator_title(title: str, feed_url: str) -> str:
    """Google News appends ' - Outlet' to titles; strip it."""
    if "news.google.com" in feed_url and " - " in title:
        return title.rsplit(" - ", 1)[0].strip()
    return title


# ---------------------------------------------------------------------------
# Collectors. Each returns list[Item]. Each is wrapped by safe_collect.
# ---------------------------------------------------------------------------

def collect_cisa_kev() -> list[Item]:
    data = http_json(C.CISA_KEV_URL)
    out = []
    for v in data.get("vulnerabilities", []):
        cve = v.get("cveID", "")
        added = to_dt(v.get("dateAdded"))
        ransomware = str(v.get("knownRansomwareCampaignUse", "")).lower() == "known"
        vendor, product = v.get("vendorProject", ""), v.get("product", "")
        title = f"CISA KEV: {cve} added — {vendor} {product}: {v.get('vulnerabilityName', '')}".strip()
        summary = " ".join(filter(None, [
            v.get("shortDescription", ""),
            f"Required action: {v.get('requiredAction', '')}" if v.get("requiredAction") else "",
            f"Due date: {v.get('dueDate')}" if v.get("dueDate") else "",
            "Known use in ransomware campaigns." if ransomware else "",
        ]))
        out.append(Item(
            id=f"kev:{cve}", source="CISA KEV", domain="cisa.gov", title=title,
            url=f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog?search_api_fulltext={cve}",
            extra_links=[f"https://nvd.nist.gov/vuln/detail/{cve}"],
            summary=summary, published=added, start_time=added, official=True,
            severity_hint=SEV_CRITICAL if ransomware else SEV_HIGH,
            organizations=[vendor] if vendor else [],
            locations=["United States (nationwide)"],
            cause=f"Confirmed (CISA): exploited vulnerability {cve}",
        ))
    return out


def collect_cisa_advisories() -> list[Item]:
    feed = http_feed(C.CISA_ADVISORIES_RSS)
    out = []
    for e in feed.entries:
        link = e.get("link", "")
        title = clean_text(e.get("title", ""))
        summary = clean_text(e.get("summary", "") or e.get("description", ""))
        pub = to_dt(e.get("published_parsed") or e.get("updated_parsed"))
        hint = None
        if re.search(r"emergency directive", title + summary, re.I):
            hint = SEV_CRITICAL
        elif re.search(r"CISA (Adds|Releases) .*(Known Exploited|ICS Advisor|Advisories)", title, re.I):
            hint = SEV_LOW  # roll-up posts; the underlying items arrive via KEV / their own entries
        elif title.lower().startswith("ics"):
            hint = SEV_MODERATE
        out.append(Item(
            id=f"cisa:{stable_id(link or title)}", source="CISA Advisories", domain="cisa.gov",
            title=f"CISA: {title}", url=link, summary=summary, published=pub,
            official=True, severity_hint=hint, organizations=["CISA"],
            locations=["United States (nationwide)"],
            cause="Confirmed (CISA): see advisory",
        ))
    return out


_NWS_SKIP_TYPES = {"Cancel", "Ack", "Error"}


def collect_nws() -> list[Item]:
    data = http_json(C.NWS_ALERTS_URL, headers={"User-Agent": C.NWS_USER_AGENT, "Accept": "application/geo+json"})
    out = []
    for f in data.get("features", []):
        p = f.get("properties", {})
        if p.get("messageType") in _NWS_SKIP_TYPES:
            continue
        event = p.get("event", "Weather alert")
        sev = p.get("severity", "")
        ugc = (p.get("geocode") or {}).get("UGC") or []
        states = sorted({ABBR_TO_STATE.get(c[:2], c[:2]) for c in ugc if len(c) >= 2})
        area = clean_text(p.get("areaDesc", ""))
        headline = clean_text(p.get("headline", "")) or event
        desc = clean_text(p.get("description", ""))
        instr = clean_text(p.get("instruction", ""))
        if sev == "Extreme":
            hint = SEV_CRITICAL
        elif event in C.NWS_HIGH_EVENTS:
            hint = SEV_HIGH
        elif event in C.NWS_MODERATE_EVENTS:
            hint = SEV_MODERATE
        else:
            hint = SEV_LOW
        onset = p.get("onset") or p.get("effective") or ""
        out.append(Item(
            id=f"nws:{stable_id(event, area, str(onset)[:16])}", source="NWS Alerts", domain="weather.gov",
            title=f"NWS {event} ({sev}): {truncate(area, 120)}",
            url=f.get("id") or "https://alerts.weather.gov/",
            summary=truncate(" ".join(filter(None, [headline, desc, instr])), 600),
            published=to_dt(p.get("sent")), start_time=to_dt(p.get("onset") or p.get("effective")),
            official=True, severity_hint=hint,
            locations=states or [area], organizations=[clean_text(p.get("senderName", "NWS"))],
            cause=f"Confirmed (NWS): {event}",
        ))
    return out


def _usgs_is_us(place: str) -> bool:
    if RX_STATES.search(place) or RX_STATE_ABBR.search(place):
        return True
    return bool(re.search(r"\b(Alaska|Hawaii|Puerto Rico|Guam|Virgin Islands|American Samoa|Northern Mariana|U\.S\.|United States|CA|TX|OK|NV|UT|WA|OR|ID|MT|WY)\b", place))


def collect_usgs() -> list[Item]:
    data = http_json(C.USGS_SIGNIFICANT_URL)
    out = []
    for f in data.get("features", []):
        p = f.get("properties", {})
        place = p.get("place") or ""
        if not _usgs_is_us(place):
            continue
        mag = float(p.get("mag") or 0)
        when = to_dt(p.get("time"))
        tsunami = bool(p.get("tsunami"))
        hint = SEV_CRITICAL if (mag >= C.USGS_CRITICAL_MAGNITUDE or tsunami) else SEV_HIGH
        locs = [m.group(1) for m in RX_STATES.finditer(place)]
        locs += [ABBR_TO_STATE[m.group(1)] for m in RX_STATE_ABBR.finditer(place) if m.group(1) in ABBR_TO_STATE]
        out.append(Item(
            id=f"usgs:{f.get('id')}", source="USGS Earthquakes", domain="usgs.gov",
            title=f"USGS M{mag:.1f} earthquake — {place}",
            url=p.get("url") or "https://earthquake.usgs.gov/",
            summary=f"Magnitude {mag:.1f}, {place}. PAGER alert level: {p.get('alert') or 'none'}. "
                    f"Tsunami flag: {'yes' if tsunami else 'no'}. Felt reports: {p.get('felt') or 0}.",
            published=when, start_time=when, official=True, severity_hint=hint,
            locations=sorted(set(locs)) or [place], organizations=["USGS"],
            cause=f"Confirmed (USGS): earthquake M{mag:.1f}",
        ))
    return out


def collect_fema() -> list[Item]:
    data = http_json(C.FEMA_DECLARATIONS_URL)
    by_number: dict[int, dict] = {}
    for d in data.get("DisasterDeclarationsSummaries", []):
        n = d.get("disasterNumber")
        g = by_number.setdefault(n, {"rec": d, "areas": []})
        if d.get("designatedArea"):
            g["areas"].append(d["designatedArea"])
    out = []
    for n, g in by_number.items():
        d = g["rec"]
        dtype = d.get("declarationType", "")
        kind = {"DR": "Major Disaster Declaration", "EM": "Emergency Declaration",
                "FM": "Fire Management Assistance Declaration"}.get(dtype, f"Declaration ({dtype})")
        state = ABBR_TO_STATE.get(d.get("state", ""), d.get("state", ""))
        areas = sorted(set(g["areas"]))
        declared = to_dt(d.get("declarationDate"))
        out.append(Item(
            id=f"fema:{n}", source="FEMA Declarations", domain="fema.gov",
            title=f"FEMA {kind}: {d.get('declarationTitle', '')} ({state})",
            url=f"https://www.fema.gov/disaster/{n}",
            summary=f"{d.get('incidentType', '')} incident. Declared {fmt_dt(declared)}. "
                    f"Designated areas ({len(areas)}): {truncate('; '.join(areas), 300)}",
            published=declared, start_time=to_dt(d.get("incidentBeginDate")),
            official=True, severity_hint=SEV_MODERATE if dtype == "FM" else SEV_HIGH,
            locations=[state], organizations=["FEMA"],
            cause=f"Confirmed (FEMA): {d.get('incidentType', 'incident')}",
        ))
    return out


_OFAC_RX = re.compile(r'<a[^>]+href="(/recent-actions/(\d{8})[^"]*)"[^>]*>([^<]+)</a>', re.I)


def collect_ofac() -> list[Item]:
    page = http_get(C.OFAC_RECENT_ACTIONS_URL).text
    out, seen_local = [], set()
    for href, ymd, title in _OFAC_RX.findall(page):
        title = clean_text(title)
        if (href, title) in seen_local:
            continue
        seen_local.add((href, title))
        pub = to_dt(f"{ymd[:4]}-{ymd[4:6]}-{ymd[6:]}")
        out.append(Item(
            id=f"ofac:{ymd}:{stable_id(title)}", source="Treasury OFAC", domain="treasury.gov",
            title=f"OFAC: {title}", url=f"https://ofac.treasury.gov{href}",
            summary=f"Recent action published by the Office of Foreign Assets Control on {ymd[:4]}-{ymd[4:6]}-{ymd[6:]}.",
            published=pub, start_time=pub, official=True, organizations=["Treasury", "OFAC"],
            severity_hint=SEV_MODERATE,
            locations=["United States (federal action)"],
            cause="Confirmed (Treasury): official sanctions action",
        ))
    if not out:
        raise SourceError("OFAC page parsed but no recent actions found (layout change?)")
    return out


def collect_state_dept() -> list[Item]:
    feed, used = http_feed_any([C.STATE_DEPT_RSS] + C.STATE_DEPT_FALLBACK_RSS)
    via = "" if used == C.STATE_DEPT_RSS else f" (via {domain_of(used)} index of state.gov)"
    out = []
    for e in feed.entries:
        title = aggregator_title(clean_text(e.get("title", "")), used)
        link = unwrap_aggregator_link(e.get("link", ""))
        if not title or not link:
            continue
        if is_aggregator(used) and base_domain(entry_domain(e, link, used, "")) != "state.gov":
            continue  # aggregator returned something that is not a state.gov release
        out.append(Item(
            id=f"state:{stable_id(link or title)}", source="State Department", domain="state.gov",
            title=f"State Dept: {title}", url=link,
            summary=truncate(clean_text(e.get("summary", "")), 500) + via,
            published=to_dt(e.get("published_parsed") or e.get("updated_parsed")),
            official=True, organizations=["State Department"],
            locations=["United States (federal statement)"],
            cause="Confirmed (State Department): official statement",
        ))
    return out


def _news_collector(name: str, urls: list[str], outlet_domain: str | None) -> Callable[[], list[Item]]:
    """outlet_domain=None means a topic feed: accept every domain, tag by real source."""
    def collect() -> list[Item]:
        feed, used = http_feed_any(urls)
        out = []
        for e in feed.entries:
            link = unwrap_aggregator_link(e.get("link", ""))
            title = aggregator_title(clean_text(e.get("title", "")), used)
            if not title or not link:
                continue
            dom = entry_domain(e, link, used, outlet_domain or "")
            if outlet_domain and is_aggregator(used) and base_domain(dom) != base_domain(outlet_domain):
                continue  # only accept the outlet this feed is supposed to represent
            if not dom or dom.endswith("news.google.com"):
                continue  # topic feed entry with no identifiable origin
            out.append(Item(
                id=f"news:{stable_id(link or title)}", source=name, domain=dom, title=title, url=link,
                summary=truncate(clean_text(e.get("summary", "") or e.get("description", "")), 500),
                published=to_dt(e.get("published_parsed") or e.get("updated_parsed")), is_news=True,
            ))
        return out
    return collect


SOURCES: list[tuple[str, Callable[[], list[Item]]]] = [
    ("CISA KEV", collect_cisa_kev),
    ("CISA Advisories", collect_cisa_advisories),
    ("NWS Alerts", collect_nws),
    ("USGS Earthquakes", collect_usgs),
    ("FEMA Declarations", collect_fema),
    ("Treasury OFAC", collect_ofac),
    ("State Department", collect_state_dept),
    (C.IRAN_US_FEED[0], _news_collector(C.IRAN_US_FEED[0], C.IRAN_US_FEED[1], None)),
] + [(n, _news_collector(n, u, d)) for n, u, d in C.NEWS_FEEDS]


def safe_collect(name: str, fn: Callable[[], list[Item]], failures: dict[str, str]) -> list[Item]:
    """Run one collector with a hard wall-clock limit. A hung socket must not
    stall the whole run (GitHub Actions kills the job at 10 minutes)."""
    result: dict[str, object] = {}

    def target() -> None:
        try:
            result["items"] = fn()
        except Exception as exc:  # noqa: BLE001
            result["error"] = exc

    t = threading.Thread(target=target, name=f"collect-{name}", daemon=True)
    t.start()
    t.join(C.SOURCE_TIME_LIMIT_SECONDS)
    if t.is_alive():
        failures[name] = f"timed out after {C.SOURCE_TIME_LIMIT_SECONDS}s (source abandoned for this run)"
        log.error("%-22s TIMED OUT", name)
        return []
    if "error" in result:
        failures[name] = str(result["error"])
        log.error("%-22s FAILED: %s", name, result["error"])
        return []
    items = result.get("items") or []
    log.info("%-22s fetched %d", name, len(items))
    return items  # type: ignore[return-value]


# ---------------------------------------------------------------------------
# Relevance
# ---------------------------------------------------------------------------

def us_indicator(text: str) -> bool:
    return bool(RX_US.search(text) or RX_STATES.search(text) or RX_CITIES.search(text) or RX_STATE_ABBR.search(text))


def is_relevant(item: Item) -> bool:
    t = item.text
    if item.source in ("CISA KEV", "CISA Advisories", "NWS Alerts", "USGS Earthquakes", "FEMA Declarations"):
        return True  # U.S. official hazard/cyber feeds are relevant by construction
    if item.source in ("Treasury OFAC", "State Department"):
        # U.S. government speaking: Iran, cyber, or infrastructure mentions qualify
        return bool(RX_IRAN.search(t) or RX_CYBER.search(t) or RX_INFRA.search(t))
    topical = RX_INFRA.search(t) or RX_CYBER.search(t) or RX_OUTAGE.search(t)
    if topical and us_indicator(t):
        return True
    if RX_IRAN.search(t) and us_indicator(t):
        return True
    return False


# ---------------------------------------------------------------------------
# Enrichment + classification
# ---------------------------------------------------------------------------

def extract_locations(text: str) -> list[str]:
    locs: list[str] = []
    for m in RX_STATES.finditer(text):
        locs.append(m.group(1))
    for m in RX_STATE_ABBR.finditer(text):
        locs.append(ABBR_TO_STATE.get(m.group(1), m.group(1)))
    for m in RX_CITIES.finditer(text):
        locs.append(m.group(0))
    if re.search(r"\b(nationwide|across the (u\.s\.|united states|country))\b", text, re.I):
        locs.append("United States (nationwide)")
    seen, out = set(), []
    for l in locs:
        if l not in seen:
            seen.add(l)
            out.append(l)
    return out[:8]


def extract_orgs(text: str) -> list[str]:
    found = []
    for m in RX_ORGS.finditer(text):
        name = m.group(0)
        if name not in found:
            found.append(name)
    return found[:6]


def enrich(item: Item) -> None:
    if not item.locations:
        item.locations = extract_locations(item.text) or ["Not specified in source"]
    orgs = extract_orgs(item.text)
    for o in orgs:
        if o not in item.organizations:
            item.organizations.append(o)
    item.organizations = item.organizations[:6] or ["Not specified in source"]
    if not item.official:
        item.cause = "Unknown (not confirmed by an official source)"
        if RX_RESTRICTED.search(item.text):
            item.notes.append(
                "Terms such as terrorism, sabotage or coordinated attack in this headline are the "
                "outlet's characterization. No official source has confirmed a cause."
            )


def assign_verification(item: Item) -> None:
    if item.official or is_official_domain(item.domain):
        item.verification = V_CONFIRMED
    elif item.corroborators:
        item.verification = V_CORROBORATED
    elif is_credible_domain(item.domain):
        item.verification = V_UNV_CREDIBLE
    else:
        item.verification = V_UNV_UNKNOWN


def assign_severity(item: Item) -> None:
    text = item.text
    if item.severity_hint:
        sev = item.severity_hint
        # keyword rules may raise but not lower a source-specific hint
        if RX_CRITICAL.search(text) and SEV_RANK[sev] < SEV_RANK[SEV_CRITICAL] and item.source not in ("NWS Alerts", "CISA Advisories"):
            sev = SEV_CRITICAL
    elif RX_CRITICAL.search(text):
        sev = SEV_CRITICAL
    elif RX_HIGH.search(text):
        sev = SEV_HIGH
    else:
        sev = SEV_MODERATE
    if item.verification == V_UNV_UNKNOWN and SEV_RANK[sev] > SEV_RANK[SEV_HIGH]:
        sev = SEV_HIGH  # an unknown source alone cannot drive Critical
        item.notes.append("Severity capped at High because the only source is unknown.")
    if not item.official and SEV_RANK[sev] > SEV_RANK[SEV_MODERATE] and RX_AFTERMATH.search(item.title):
        sev = SEV_MODERATE
        item.notes.append("Severity set to Moderate: headline describes aftermath (arrest, lawsuit, hearing), not an active incident.")
    item.severity = sev


def cluster_corroboration(news: list[Item], recent_seen: list[dict]) -> list[Item]:
    """Group news items about the same story from independent domains.
    Returns the representative items to alert on; siblings are folded in."""
    def similar(a: set[str], b: set[str]) -> bool:
        if not a or not b:
            return False
        inter = len(a & b)
        if inter >= 4 and (inter / min(len(a), len(b))) >= 0.75:
            return True
        return inter / len(a | b) >= 0.5

    toks = {it.id: title_tokens(it.title) for it in news}
    assigned: dict[str, int] = {}
    clusters: list[list[Item]] = []
    for it in news:
        placed = False
        for ci, members in enumerate(clusters):
            if any(similar(toks[it.id], toks[m.id]) for m in members):
                members.append(it)
                assigned[it.id] = ci
                placed = True
                break
        if not placed:
            assigned[it.id] = len(clusters)
            clusters.append([it])

    reps: list[Item] = []
    for members in clusters:
        # prefer credible > unknown, then earliest published
        members.sort(key=lambda m: (0 if is_credible_domain(m.domain) else 1, m.published or NOW))
        rep = members[0]
        domains = {base_domain(rep.domain)}
        for m in members[1:]:
            d = base_domain(m.domain)
            if d not in domains:
                domains.add(d)
                if is_credible_domain(m.domain) or is_official_domain(m.domain):
                    rep.corroborators.append(m.domain)
            if m.url and m.url not in rep.extra_links and m.url != rep.url:
                rep.extra_links.append(m.url)
        # corroboration from items alerted in earlier runs (same story, other outlet)
        for s in recent_seen:
            if base_domain(s.get("d", "")) in domains:
                continue
            if similar(toks[rep.id], set(s.get("k", []))) and (is_credible_domain(s.get("d", "")) or is_official_domain(s.get("d", ""))):
                rep.corroborators.append(s["d"])
                domains.add(base_domain(s["d"]))
                if s.get("u"):
                    rep.extra_links.append(s["u"])
        if len(members) > 1:
            rep.notes.append(f"{len(members)} reports on this story in this run.")
        rep.corroborators = sorted(set(rep.corroborators))
        reps.append(rep)
    return reps


# ---------------------------------------------------------------------------
# State (seen.json)
# ---------------------------------------------------------------------------

def load_state(path: str) -> tuple[dict, bool]:
    if not os.path.exists(path):
        return {"version": 1, "last_digest_at": None, "pending_digest": [], "seen": {}}, True
    with open(path, "r", encoding="utf-8") as fh:
        st = json.load(fh)
    st.setdefault("version", 1)
    st.setdefault("last_digest_at", None)
    st.setdefault("pending_digest", [])
    st.setdefault("seen", {})
    return st, False


def save_state(path: str, st: dict) -> None:
    cutoff = NOW - timedelta(days=C.SEEN_RETENTION_DAYS)
    st["seen"] = {k: v for k, v in st["seen"].items() if to_dt(v.get("t")) and to_dt(v["t"]) >= cutoff}
    st["last_run_at"] = NOW.isoformat()
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(st, fh, indent=1, ensure_ascii=False, sort_keys=True)


def mark_seen(st: dict, item: Item, disposition: str) -> None:
    rec = {"t": NOW.isoformat(), "s": item.source, "sev": item.severity, "v": item.verification, "x": disposition}
    if item.is_news:
        rec.update({"d": item.domain, "k": sorted(title_tokens(item.title)), "u": item.url, "title": truncate(item.title, 140)})
    st["seen"][item.id] = rec


def recent_news_seen(st: dict, hours: int = 48) -> list[dict]:
    cutoff = NOW - timedelta(hours=hours)
    out = []
    for v in st["seen"].values():
        t = to_dt(v.get("t"))
        if t and t >= cutoff and v.get("k"):
            out.append(v)
    return out


# ---------------------------------------------------------------------------
# alerts/recent.json: the hand-off to the scheduled Claude routine
# ---------------------------------------------------------------------------

def alert_record(item: Item, disposition: str) -> dict:
    return {
        "id": item.id,
        "severity": item.severity,
        "verification": item.verification,
        "unverified": item.unverified,
        "title": display_title(item),
        "detected": NOW.isoformat(),
        "published": item.published.isoformat() if item.published else None,
        "start_time": item.start_time.isoformat() if item.start_time else None,
        "locations": item.locations,
        "organizations": item.organizations,
        "impact_as_reported": item.summary or "Not stated in source",
        "cause": item.cause,
        "source": item.source,
        "source_domain": item.domain,
        "corroborated_by": item.corroborators,
        "links": [item.url] + item.extra_links[:6],
        "notes": item.notes,
        "disposition": disposition,   # immediate | digest | logged
    }


def load_alerts(path: str) -> dict:
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as fh:
                return json.load(fh)
        except Exception as exc:  # noqa: BLE001
            log.warning("alerts file unreadable, starting fresh: %s", exc)
    return {"alerts": []}


def save_alerts(path: str, doc: dict, new_records: list[dict], failures: dict[str, str], note: str = "") -> None:
    cutoff = NOW - timedelta(hours=ALERTS_RETENTION_HOURS)
    kept = [a for a in doc.get("alerts", []) if (to_dt(a.get("detected")) or NOW) >= cutoff]
    kept.extend(new_records)
    kept.sort(key=lambda a: (a.get("detected") or ""), reverse=True)
    out = {
        "generated": NOW.isoformat(),
        "retention_hours": ALERTS_RETENTION_HOURS,
        "note": note or "Alerts from the last 48 hours, newest first. 'detected' is when the monitor first saw the item.",
        "source_failures": failures,
        "counts": {sev: sum(1 for a in kept if a["severity"] == sev) for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MODERATE, SEV_LOW)},
        "alerts": kept,
    }
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(out, fh, indent=1, ensure_ascii=False)


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------

def display_title(item: Item) -> str:
    return ("UNVERIFIED: " if item.unverified else "") + item.title


def sev_tag(sev: str) -> str:
    return {SEV_CRITICAL: "[CRITICAL]", SEV_HIGH: "[HIGH]", SEV_MODERATE: "[MODERATE]", SEV_LOW: "[LOW]"}[sev]


def render_alert(item: Item) -> str:
    verification = item.verification
    if item.corroborators:
        verification += f" (also reported by: {', '.join(item.corroborators)})"
    elif not item.official:
        verification += f" ({item.domain or 'unknown domain'})"
    lines = [
        f"{sev_tag(item.severity)} {display_title(item)}",
        "",
        f"Severity:        {item.severity}",
        f"Verification:    {verification}",
        f"Detected:        {fmt_dt(NOW)}",
        f"Start time:      {fmt_dt(item.start_time) if item.start_time else 'Not stated'}",
        f"Published:       {fmt_dt(item.published)}",
        f"Locations:       {'; '.join(item.locations)}",
        f"Organizations:   {'; '.join(item.organizations)}",
        f"Impact (as reported): {item.summary or 'Not stated in source'}",
        f"Cause:           {item.cause}",
        f"Source:          {item.source}" + ("" if item.official else f" via {item.domain}"),
        "Links:",
        f"  - {item.url}",
    ]
    lines += [f"  - {u}" for u in item.extra_links[:6]]
    for n in item.notes:
        lines.append(f"Note: {n}")
    return "\n".join(lines)


def render_sms(item: Item) -> str:
    sev = {SEV_CRITICAL: "CRIT", SEV_HIGH: "HIGH"}.get(item.severity, item.severity.upper())
    loc = item.locations[0] if item.locations else ""
    if loc.startswith("Not") or loc.startswith("United States ("):
        loc = ""
    head = f"[{sev}] {'UNVERIFIED ' if item.unverified else ''}"
    tail = f" ({loc})" if loc else ""
    budget = notify.SMS_MAX_CHARS - len(head) - len(tail) - len(" -details emailed")
    return f"{head}{truncate(item.title, max(budget, 30))}{tail} -details emailed"


def render_compact(item: Item) -> str:
    ver = item.verification
    if item.corroborators:
        ver += f" (+{', '.join(item.corroborators)})"
    elif not item.official:
        ver += f" ({item.domain})"
    lines = [
        f"• {display_title(item)}",
        f"  {ver} | {'; '.join(item.locations[:3])} | start {fmt_dt(item.start_time)} | published {fmt_dt(item.published)}",
        f"  Impact: {truncate(item.summary or 'Not stated in source', 220)}",
        f"  Cause: {item.cause}",
        f"  {item.url}",
    ]
    for n in item.notes:
        lines.append(f"  Note: {n}")
    return "\n".join(lines)


def render_digest(entries: list[dict], failures: dict[str, str]) -> tuple[str, str]:
    by_sev: dict[str, list[dict]] = {}
    for e in entries:
        by_sev.setdefault(e["severity"], []).append(e)
    parts = [f"U.S. Infrastructure & Cyber Threat Monitor — digest {fmt_dt(NOW)}",
             f"{len(entries)} item(s) since the last digest.", ""]
    for sev in (SEV_CRITICAL, SEV_HIGH, SEV_MODERATE, SEV_LOW):
        group = by_sev.get(sev)
        if not group:
            continue
        parts.append(f"==== {sev.upper()} ({len(group)}) ====")
        for e in group:
            parts.append(e["text"])
            parts.append("")
        parts.append("")
    if failures:
        parts.append("==== Source health (this run) ====")
        for k, v in failures.items():
            parts.append(f"  {k}: {truncate(v, 160)}")
    subject = f"[DIGEST] {len(entries)} item(s) — U.S. Infra & Cyber Monitor {NOW.strftime('%Y-%m-%d %H:%M UTC')}"
    return subject, "\n".join(parts)


# ---------------------------------------------------------------------------
# Main pipeline
# ---------------------------------------------------------------------------

def run(state_path: str, alerts_path: str = ALERTS_FILE_DEFAULT, force_digest: bool = False) -> int:
    st, first_run = load_state(state_path)
    alerts_doc = load_alerts(alerts_path)
    email_on = notify.email_configured() or notify.dry_run()
    failures: dict[str, str] = {}
    lookback = NOW - timedelta(hours=C.LOOKBACK_HOURS)

    # 1. collect
    collected: list[Item] = []
    for name, fn in SOURCES:
        collected.extend(safe_collect(name, fn, failures))
        time.sleep(0.5)

    # 2. age + seen + relevance filters
    fresh: list[Item] = []
    stats = {"collected": len(collected), "old": 0, "seen": 0, "irrelevant": 0}
    for it in collected:
        if it.published and it.published < lookback:
            stats["old"] += 1
            continue
        if it.id in st["seen"]:
            stats["seen"] += 1
            continue
        if not is_relevant(it):
            stats["irrelevant"] += 1
            continue
        fresh.append(it)

    # 3. corroboration clustering for news-type items
    news = [it for it in fresh if it.is_news]
    others = [it for it in fresh if not it.is_news]
    reps = cluster_corroboration(news, recent_news_seen(st)) if news else []
    folded = {it.id for it in news} - {r.id for r in reps}
    for it in news:
        if it.id in folded:
            mark_seen(st, it, "folded")

    candidates = others + reps
    for it in candidates:
        enrich(it)
        assign_verification(it)
        assign_severity(it)
    candidates.sort(key=lambda i: (-SEV_RANK[i.severity], i.published or NOW))

    # 4. bootstrap: first ever run records everything and sends nothing
    if first_run:
        for it in candidates:
            mark_seen(st, it, "bootstrap")
        save_state(state_path, st)
        save_alerts(alerts_path, alerts_doc, [], failures,
                    note=f"Bootstrap run at {fmt_dt(NOW)}: {len(candidates)} current items recorded as seen, none alerted.")
        msg = (f"Monitor initialized at {fmt_dt(NOW)}.\n"
               f"{len(candidates)} current item(s) were recorded as already seen so the first run "
               f"does not flood you. Alerts begin with the next run.\n\n"
               f"Sources OK: {len(SOURCES) - len(failures)}/{len(SOURCES)}\n"
               + ("Failures:\n" + "\n".join(f"  {k}: {v}" for k, v in failures.items()) if failures else ""))
        if email_on:
            notify.send_email("[INIT] U.S. Infra & Cyber Monitor is running", msg)
        log.info("Bootstrap complete; %d items recorded, nothing sent.", len(candidates))
        print(msg)
        return 0

    # 5. dispatch
    immediate = [it for it in candidates if it.severity in (SEV_CRITICAL, SEV_HIGH)]
    moderate = [it for it in candidates if it.severity == SEV_MODERATE]
    low = [it for it in candidates if it.severity == SEV_LOW]

    new_records: list[dict] = []
    sent_immediate = 0
    for it in immediate:
        new_records.append(alert_record(it, "immediate"))
        if email_on and sent_immediate < C.MAX_IMMEDIATE_PER_RUN:
            subject = f"{sev_tag(it.severity)} {truncate(display_title(it), 140)}"
            notify.send_email(subject, render_alert(it))
            notify.send_sms(render_sms(it))
            mark_seen(st, it, "immediate")
            sent_immediate += 1
        elif email_on:
            it.notes.append("Deferred to digest: per-run immediate alert cap reached.")
            st["pending_digest"].append({"severity": it.severity, "text": render_compact(it), "t": NOW.isoformat()})
            mark_seen(st, it, "digest-overflow")
        else:
            mark_seen(st, it, "immediate")

    for it in moderate:
        new_records.append(alert_record(it, "digest"))
        if email_on:
            st["pending_digest"].append({"severity": it.severity, "text": render_compact(it), "t": NOW.isoformat()})
        mark_seen(st, it, "digest")

    for it in low:
        new_records.append(alert_record(it, "logged"))
        log.info("LOW (logged only): %s", display_title(it))
        mark_seen(st, it, "logged")

    # 6. digest timer (email path only)
    if email_on:
        last_digest = to_dt(st.get("last_digest_at"))
        due = force_digest or last_digest is None or (NOW - last_digest) >= timedelta(hours=C.DIGEST_INTERVAL_HOURS)
        if due and st["pending_digest"]:
            subject, body = render_digest(st["pending_digest"], failures)
            if notify.send_email(subject, body) or notify.dry_run():
                st["pending_digest"] = []
                st["last_digest_at"] = NOW.isoformat()
        elif due and last_digest is None:
            st["last_digest_at"] = NOW.isoformat()

    save_state(state_path, st)
    save_alerts(alerts_path, alerts_doc, new_records, failures)

    # 7. summary
    print("\n" + "=" * 70)
    print(f"RUN SUMMARY {fmt_dt(NOW)}")
    print(f"  collected={stats['collected']} too_old={stats['old']} already_seen={stats['seen']} "
          f"irrelevant={stats['irrelevant']} new={len(fresh)} folded_dupes={len(folded)}")
    print(f"  delivery={'email+sms' if email_on else 'repo file only'} immediate={len(immediate)} (emailed {sent_immediate}) "
          f"moderate={len(moderate)} low_logged={len(low)} digest_pending={len(st['pending_digest'])}")
    print(f"  alerts file: {alerts_path}")
    if failures:
        print("  SOURCE FAILURES:")
        for k, v in failures.items():
            print(f"    - {k}: {truncate(v, 160)}")
    print("=" * 70)
    for it in candidates:
        print(f"  {sev_tag(it.severity):11} {it.verification:28} {truncate(display_title(it), 90)}")
    return 0


def report_failure(detail: str) -> None:
    run_url = ""
    if os.environ.get("GITHUB_RUN_ID"):
        run_url = (f"{os.environ.get('GITHUB_SERVER_URL', 'https://github.com')}/"
                   f"{os.environ.get('GITHUB_REPOSITORY', '')}/actions/runs/{os.environ['GITHUB_RUN_ID']}")
    body = f"The monitor run at {fmt_dt(NOW)} failed.\n\n{detail}\n\n{run_url}"
    notify.send_email("[MONITOR FAILURE] U.S. Infra & Cyber Monitor", body)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--state", default=os.environ.get("STATE_FILE", STATE_FILE_DEFAULT))
    ap.add_argument("--alerts", default=os.environ.get("ALERTS_FILE", ALERTS_FILE_DEFAULT))
    ap.add_argument("--dry-run", action="store_true", help="print instead of sending")
    ap.add_argument("--force-digest", action="store_true")
    ap.add_argument("--report-failure", action="store_true", help="email a failure notice and exit")
    ap.add_argument("--test-delivery", action="store_true", help="send one test email and one test text, then exit")
    ap.add_argument("-v", "--verbose", action="store_true")
    args = ap.parse_args(argv)

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(name)s: %(message)s", stream=sys.stderr)
    if args.dry_run:
        os.environ["DRY_RUN"] = "1"

    if args.report_failure:
        report_failure("GitHub Actions reported the job as failed (see run log).")
        return 0
    if args.test_delivery:
        ok_mail = notify.send_email("[TEST] U.S. Infra & Cyber Monitor delivery check",
                                    f"Email delivery works. Sent {fmt_dt(NOW)}.")
        ok_sms = notify.send_sms(f"[TEST] US Infra & Cyber Monitor: text delivery works ({NOW.strftime('%H:%M')} UTC)")
        print(f"email={'ok' if ok_mail else 'FAILED'} sms={'ok' if ok_sms else 'FAILED or not configured'}")
        return 0 if ok_mail else 1

    try:
        return run(args.state, alerts_path=args.alerts, force_digest=args.force_digest)
    except Exception:  # noqa: BLE001
        tb = traceback.format_exc()
        log.error("Monitor crashed:\n%s", tb)
        try:
            report_failure(tb)
        except Exception as exc:  # noqa: BLE001
            log.error("Failure email could not be sent: %s", exc)
        return 1


if __name__ == "__main__":
    sys.exit(main())

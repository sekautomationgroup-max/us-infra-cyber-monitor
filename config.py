"""
Tunable rules for the U.S. Infrastructure & Cyber Threat Monitor.

Everything a non-programmer might want to adjust lives here:
feed URLs, keyword lists, credible-outlet list, severity rules, limits.
No credentials belong in this file. Credentials come from environment
variables (GitHub Secrets) and are read in notify.py.
"""

# ---------------------------------------------------------------------------
# Run behaviour
# ---------------------------------------------------------------------------

# Items older than this are marked seen but never alerted on. Protects the
# first run (and any run after a long outage) from sending a flood of old news.
LOOKBACK_HOURS = 24

# Safety valve: at most this many Critical/High alerts are sent immediately per
# run. Anything beyond that is folded into the next digest with a note.
MAX_IMMEDIATE_PER_RUN = 10

# Moderate items are batched and emailed once this many hours have passed
# since the last digest.
DIGEST_INTERVAL_HOURS = 6

# How long a seen item stays in seen.json before it is pruned.
SEEN_RETENTION_DAYS = 14

# Network settings
SOURCE_TIME_LIMIT_SECONDS = 75   # hard wall-clock cap per source, retries included
HTTP_TIMEOUT_SECONDS = 20
HTTP_RETRIES = 3
HTTP_RETRY_BACKOFF_SECONDS = 4  # multiplied by attempt number

# Browser-like UA: state.gov blocks generic clients, api.weather.gov requires
# a UA with contact info. We send this to everything except NWS.
USER_AGENT = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/130.0 Safari/537.36 us-infra-monitor/1.0"
)
NWS_USER_AGENT = "us-infra-monitor/1.0 (github actions; see repo README)"

# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CISA_ADVISORIES_RSS = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
NWS_ALERTS_URL = "https://api.weather.gov/alerts/active?status=actual&severity=Extreme,Severe"
USGS_SIGNIFICANT_URL = "https://earthquake.usgs.gov/earthquakes/feed/v1.0/summary/significant_week.geojson"
FEMA_DECLARATIONS_URL = (
    "https://www.fema.gov/api/open/v2/DisasterDeclarationsSummaries"
    "?$orderby=declarationDate%20desc&$top=60"
)
OFAC_RECENT_ACTIONS_URL = "https://ofac.treasury.gov/recent-actions"
STATE_DEPT_RSS = "https://www.state.gov/rss-feed/press-releases/feed/"
# state.gov refuses datacenter IPs (HTTP 405 from GitHub runners). Fallback:
# Google News index of state.gov, which links through to the original releases.
STATE_DEPT_FALLBACK_RSS = [
    "https://news.google.com/rss/search?q=site:state.gov+when:1d&hl=en-US&gl=US&ceid=US:en",
    "https://www.bing.com/news/search?q=site%3Astate.gov&format=RSS",
]

# GDELT DOC 2.0 API. Rate limited to one request per 5 seconds per IP and it
# returns HTTP 429 freely; the fetcher treats that as a soft failure.
GDELT_URL = (
    "https://api.gdeltproject.org/api/v2/doc/doc"
    "?query=(Iran%20OR%20Iranian%20OR%20IRGC)%20%22United%20States%22%20sourcelang:english"
    "&mode=ArtList&format=json&timespan=2h&maxrecords=75&sort=DateDesc"
)

# AP and Reuters no longer publish public RSS feeds, so we use Google News'
# site-restricted RSS search, which links through to the original articles.
_GN = "https://news.google.com/rss/search?q={q}&hl=en-US&gl=US&ceid=US:en"
_NEWS_TERMS = (
    "(cyberattack+OR+ransomware+OR+hack+OR+breach+OR+outage+OR+blackout+OR+grid"
    "+OR+pipeline+OR+refinery+OR+%22water+system%22+OR+derailment+OR+%22ground+stop%22"
    "+OR+Iran+OR+CISA+OR+FEMA+OR+%22state+of+emergency%22)+when:1d"
)

# Bing News RSS is the fallback when Google News returns 503 to datacenter IPs.
_BING = "https://www.bing.com/news/search?q={q}&format=RSS"
_BING_TERMS = "(cyberattack+OR+ransomware+OR+outage+OR+blackout+OR+pipeline+OR+grid+OR+Iran+OR+CISA+OR+FEMA)"

NEWS_FEEDS = [
    # (name, [primary url, fallback url, ...], outlet domain used for credibility)
    ("AP News", [_GN.format(q="site:apnews.com+" + _NEWS_TERMS),
                 _BING.format(q="site%3Aapnews.com+" + _BING_TERMS)], "apnews.com"),
    ("Reuters", [_GN.format(q="site:reuters.com+" + _NEWS_TERMS),
                 _BING.format(q="site%3Areuters.com+" + _BING_TERMS)], "reuters.com"),
    ("BleepingComputer", ["https://www.bleepingcomputer.com/feed/"], "bleepingcomputer.com"),
    ("The Record", ["https://therecord.media/feed"], "therecord.media"),
    ("SecurityWeek", ["https://www.securityweek.com/feed/"], "securityweek.com"),
]

# ---------------------------------------------------------------------------
# Credibility
# ---------------------------------------------------------------------------

# Official sources: items are tagged "Confirmed". Matched against the item's
# source domain.
OFFICIAL_DOMAINS = {
    "cisa.gov", "weather.gov", "usgs.gov", "fema.gov", "treasury.gov",
    "state.gov", "whitehouse.gov", "dhs.gov", "fbi.gov", "nsa.gov", "doe.gov",
    "energy.gov", "epa.gov", "faa.gov", "fcc.gov", "dot.gov", "hhs.gov",
    "defense.gov", "justice.gov", "ic3.gov", "nhtsa.gov", "nrc.gov", "tsa.gov",
    "uscg.mil", "army.mil", "navy.mil", "af.mil", "ready.gov", "ferc.gov",
    "nerc.com",
}

# Established outlets: a single report is "Unverified - Credible Source".
# Two or more of these (independent domains) on the same story = "Corroborated".
CREDIBLE_DOMAINS = {
    "apnews.com", "reuters.com", "bleepingcomputer.com", "therecord.media",
    "securityweek.com", "nytimes.com", "washingtonpost.com", "wsj.com",
    "bloomberg.com", "cnn.com", "nbcnews.com", "abcnews.go.com", "cbsnews.com",
    "foxnews.com", "npr.org", "politico.com", "axios.com", "thehill.com",
    "bbc.com", "bbc.co.uk", "theguardian.com", "ft.com", "cnbc.com",
    "usatoday.com", "latimes.com", "chicagotribune.com", "bostonglobe.com",
    "wired.com", "arstechnica.com", "theverge.com", "krebsonsecurity.com",
    "cyberscoop.com", "darkreading.com", "thehackernews.com",
    "theregister.com", "zdnet.com", "techcrunch.com", "nextgov.com",
    "defenseone.com", "govinfosecurity.com", "scmagazine.com", "scworld.com",
    "utilitydive.com", "eenews.net", "spglobal.com", "upi.com", "afp.com",
    "france24.com", "dw.com", "aljazeera.com", "timesofisrael.com",
    "military.com", "stripes.com", "govexec.com", "federalnewsnetwork.com",
}

# ---------------------------------------------------------------------------
# Relevance: what counts as "about U.S. infrastructure, cyber, outages, Iran-U.S."
# A news item must hit (INFRA or CYBER or OUTAGE) AND a U.S. indicator,
# or hit IRAN AND a U.S. indicator.
# ---------------------------------------------------------------------------

INFRA_TERMS = [
    "power outage", "blackout", "power grid", "the grid", "substation",
    "transformer", "transmission line", "pipeline", "refinery", "lng",
    "natural gas", "water system", "water treatment", "water utility",
    "wastewater", "drinking water", "dam", "levee", "bridge collapse",
    "bridge closed", "rail*", "derail*", "amtrak", "freight", "airport",
    "faa", "ground stop", "air traffic", "flights grounded", "port of",
    "seaport", "shipping", "911 outage", "911 service", "telecom",
    "cell service", "cellular outage", "internet outage", "fiber cut",
    "hospital", "health system", "nuclear plant", "nuclear power",
    "chemical plant", "explosion", "plant fire", "electric utility",
    "utility", "infrastructure", "critical infrastructure", "oil terminal",
    "fuel shortage", "gas station", "highway closed", "interstate closed",
    "transit", "subway", "metro", "state of emergency", "evacuat*",
    "boil water", "data center",
]
# Matching is whole-word. A trailing * allows suffixes ("derail*" matches
# derailment). Multi-word phrases are fine.

CYBER_TERMS = [
    "cyberattack", "cyber attack", "cyber-attack", "cyber incident",
    "ransomware", "data breach", "breach", "hacked", "hackers", "hacking",
    "malware", "zero-day", "zero day", "exploited", "exploitation",
    "vulnerability", "ddos", "denial-of-service", "intrusion", "compromise",
    "compromised", "phishing", "credential*", "apt group", "nation-state",
    "state-sponsored", "threat actor*", "botnet", "wiper", "backdoor",
    "supply chain attack", "scada", "ics advisory", "ot network", "cisa", "fbi warns",
    "cyber*", "leak*", "extortion", "takedown",
]

OUTAGE_TERMS = [
    "outage", "down for", "service disruption", "disruption", "offline",
    "systems down", "network outage", "restored", "widespread",
]

IRAN_TERMS = ["iran", "iranian", "irgc", "tehran", "revolutionary guard", "quds"]

US_TERMS = [
    "united states", "u.s.", "usa", "american*", "america",
    "washington", "pentagon", "white house", "state department",
    "treasury", "congress", "senate", "centcom", "u.s. navy", "us navy",
    "federal", "nationwide", "homeland security", "dhs",
    "cisa", "fbi", "nsa", "fema", "faa", "fcc", "epa", "doe", "tsa", "hhs",
    "department of", "biden", "trump", "capitol", "coast guard",
    "us-based", "u.s.-based", "american company",
]

# All 50 states, DC, and inhabited territories. Used for location extraction
# and as a U.S. indicator.
STATES = {
    "Alabama": "AL", "Alaska": "AK", "Arizona": "AZ", "Arkansas": "AR",
    "California": "CA", "Colorado": "CO", "Connecticut": "CT", "Delaware": "DE",
    "Florida": "FL", "Georgia": "GA", "Hawaii": "HI", "Idaho": "ID",
    "Illinois": "IL", "Indiana": "IN", "Iowa": "IA", "Kansas": "KS",
    "Kentucky": "KY", "Louisiana": "LA", "Maine": "ME", "Maryland": "MD",
    "Massachusetts": "MA", "Michigan": "MI", "Minnesota": "MN",
    "Mississippi": "MS", "Missouri": "MO", "Montana": "MT", "Nebraska": "NE",
    "Nevada": "NV", "New Hampshire": "NH", "New Jersey": "NJ",
    "New Mexico": "NM", "New York": "NY", "North Carolina": "NC",
    "North Dakota": "ND", "Ohio": "OH", "Oklahoma": "OK", "Oregon": "OR",
    "Pennsylvania": "PA", "Rhode Island": "RI", "South Carolina": "SC",
    "South Dakota": "SD", "Tennessee": "TN", "Texas": "TX", "Utah": "UT",
    "Vermont": "VT", "Virginia": "VA", "Washington": "WA",
    "West Virginia": "WV", "Wisconsin": "WI", "Wyoming": "WY",
    "District of Columbia": "DC", "Puerto Rico": "PR", "Guam": "GU",
    "U.S. Virgin Islands": "VI", "American Samoa": "AS",
    "Northern Mariana Islands": "MP",
}

# Large cities as additional U.S. indicators / locations.
US_CITIES = [
    "New York City", "Los Angeles", "Chicago", "Houston", "Phoenix",
    "Philadelphia", "San Antonio", "San Diego", "Dallas", "San Jose", "Austin",
    "Jacksonville", "Fort Worth", "Columbus", "Charlotte", "Indianapolis",
    "San Francisco", "Seattle", "Denver", "Nashville", "Oklahoma City",
    "El Paso", "Boston", "Portland", "Las Vegas", "Detroit", "Memphis",
    "Louisville", "Baltimore", "Milwaukee", "Albuquerque", "Tucson",
    "Fresno", "Sacramento", "Kansas City", "Atlanta", "Omaha", "Miami",
    "Minneapolis", "Tampa", "New Orleans", "Cleveland", "Honolulu",
    "Pittsburgh", "Cincinnati", "St. Louis", "Anchorage", "Salt Lake City",
    "Washington, D.C.", "Washington, DC",
]

# Organization hints for the "organizations" field.
ORG_HINTS = [
    "CISA", "FBI", "DHS", "FEMA", "NSA", "DOE", "EPA", "FAA", "FCC", "TSA",
    "HHS", "DOT", "NRC", "FERC", "NERC", "Treasury", "OFAC", "State Department",
    "Pentagon", "CENTCOM", "Coast Guard", "National Guard", "Microsoft",
    "Google", "Amazon", "AWS", "Cisco", "Fortinet", "Palo Alto", "Ivanti",
    "Citrix", "VMware", "Oracle", "SAP", "AT&T", "Verizon", "T-Mobile",
    "Lumen", "Comcast", "Duke Energy", "PG&E", "Con Edison", "Dominion",
    "Southern Company", "Entergy", "Xcel", "ERCOT", "PJM", "MISO", "CAISO",
    "Colonial Pipeline", "Amtrak", "Union Pacific", "BNSF", "CSX",
    "Norfolk Southern", "Delta", "United Airlines", "American Airlines",
    "Southwest", "Change Healthcare", "UnitedHealth", "Kaiser", "HCA",
    "CrowdStrike", "Cloudflare", "Microsoft Azure", "IRGC", "Hezbollah",
]

# ---------------------------------------------------------------------------
# Severity keyword rules (applied after source rules; first match wins)
# ---------------------------------------------------------------------------

CRITICAL_TERMS = [
    "nationwide outage", "national emergency", "mass casualty", "emergency directive",
    "actively exploited", "grid down", "grid collapse", "pipeline shut",
    "pipeline shutdown", "refinery shutdown", "dam failure", "dam breach",
    "tsunami warning", "hurricane warning", "tornado emergency",
    "flash flood emergency", "evacuation order", "nuclear", "water supply contaminated",
    "911 outage", "911 down", "ground stop nationwide", "all flights",
    "hospital ransomware", "hospitals ransomware", "ransomware attack on",
    "shut down operations", "shuts down", "missile", "strike on", "strikes on",
    "military action", "attack on u.s.", "attack on us ", "killed",
]

HIGH_TERMS = [
    "cyberattack", "cyber attack", "ransomware", "data breach", "widespread outage",
    "power outage", "blackout", "outage", "outages", "thousands without power",
    "state of emergency", "derailment", "explosion", "ground stop nationwide",
    "tornado warning", "hurricane", "wildfire", "flash flood warning",
    "zero-day", "exploited", "breach", "breached", "hacked", "compromised", "ddos",
    "disaster declaration", "major disaster", "shut down", "shuts down",
    "disrupted", "disruption", "knocked offline", "taken offline",
]

# Stories about the aftermath of an incident (arrests, lawsuits, sentencing)
# are not active threats. For non-official sources they are capped at Moderate.
AFTERMATH_TERMS = [
    "arrested", "arrest", "extradited", "extradition", "sentenced", "sentencing",
    "pleads guilty", "pleaded guilty", "indicted", "indictment", "charged with",
    "lawsuit", "sues", "sued", "settlement", "fined", "testifies", "hearing",
    "report finds", "study finds", "analysis", "opinion", "explainer",
]

# Words that imply a cause we are not allowed to assert unless the source is
# official. If a non-official source uses them we keep the outlet's wording in
# the title but add an explicit note that the characterization is theirs.
RESTRICTED_CAUSE_TERMS = [
    "terror", "terrorism", "terrorist", "sabotage", "sabotaged",
    "coordinated attack", "coordinated attacks",
]

# NWS: event names that are severe enough to page on even at "Severe" level.
NWS_HIGH_EVENTS = {
    "Tornado Warning", "Hurricane Warning", "Tsunami Warning",
    "Flash Flood Warning", "Blizzard Warning", "Storm Surge Warning",
    "Extreme Wind Warning", "Ice Storm Warning", "Civil Danger Warning",
    "Civil Emergency Message", "Evacuation Immediate", "Hazardous Materials Warning",
    "Nuclear Power Plant Warning", "Radiological Hazard Warning",
    "Shelter In Place Warning", "Law Enforcement Warning", "Local Area Emergency",
    "911 Telephone Outage Emergency", "Fire Warning", "Volcano Warning",
}

# NWS: "Severe" events in this list go to the digest (Moderate). Any other
# "Severe" event (marine storm warnings, freezing spray, red flag, etc.) is
# logged only (Low). "Extreme" severity is always Critical.
NWS_MODERATE_EVENTS = {
    "Winter Storm Warning", "High Wind Warning", "Flood Warning",
    "Coastal Flood Warning", "Severe Thunderstorm Warning", "Excessive Heat Warning",
    "Extreme Heat Warning", "Extreme Cold Warning", "Dust Storm Warning",
    "Avalanche Warning", "Tropical Storm Warning", "Lakeshore Flood Warning",
    "Red Flag Warning", "Flood Watch", "Flash Flood Watch",
}

# USGS: magnitude at which a U.S. significant quake becomes Critical.
USGS_CRITICAL_MAGNITUDE = 6.5

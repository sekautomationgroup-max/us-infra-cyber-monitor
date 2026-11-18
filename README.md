# U.S. Infrastructure & Cyber Threat Monitor (v1)

A single Python script that runs on GitHub Actions every 5 minutes, pulls free
official and news feeds, keeps what concerns U.S. infrastructure, cyber
incidents, outages, and Iran–U.S. news, tags verification and severity, and
alerts you by email and text. Your computer can be off. No server needed.

## What runs each cycle

| Step | Detail |
|---|---|
| Pull | CISA KEV (JSON), CISA advisories (RSS), NWS active alerts (Severe + Extreme), USGS significant earthquakes, OpenFEMA declarations, Treasury OFAC recent actions, State Dept press releases, a Google News topic feed on Iran and the United States, and news from AP, Reuters, BleepingComputer, The Record, SecurityWeek |
| Filter | Items must be about U.S. infrastructure, cyber incidents, outages, or Iran news that involves the United States. All 50 states, DC and territories are recognized |
| Verify | `Confirmed` (official source), `Corroborated` (2+ independent credible outlets), `Unverified - Credible Source`, `Unverified - Unknown Source`. Unverified items are kept, never dropped, and their titles start with `UNVERIFIED:` |
| Severity | Critical / High / Moderate / Low from source rules plus keywords (see `config.py`) |
| Dedupe | `seen.json` is committed back to the repo after every run |
| Deliver | Every alert is written to `alerts/recent.json` (last 48 hours) and committed. An hourly Claude routine reads that file and notifies you: Critical + High from the past hour every run, Moderate as a digest every 6 hours, Low as a count. If Gmail secrets are set, Critical + High also go out immediately by email and text |
| Self-check | The routine warns you if `alerts/recent.json` stops updating. With email configured, a crash also emails the traceback |

Every alert includes: title, severity, verification tag, detection time, start
time if known, locations, organizations, impact as reported, cause
(Confirmed or Unknown), and source links.

### Hard rules built in

* The script never labels anything terrorism, sabotage, or a coordinated
  attack. If a non-official outlet uses those words in a headline, the alert
  carries a note that the wording is the outlet's and no official cause is
  confirmed. The `Cause` field is `Unknown` for every non-official item.
* No mock or sample data. Every alert is built from a live feed item.
* Each source is retried 3 times. A failing source is logged and reported in
  the next digest; it never stops the run.
* Credentials live only in GitHub Secrets.

## Repository layout

```
monitor.py                   the whole pipeline (collect, filter, classify, send)
config.py                    feed URLs, keyword lists, credible outlets, severity rules
notify.py                    Gmail SMTP email, carrier-gateway SMS, Twilio SMS
seen.json                    state: what was already alerted (committed by the bot)
requirements.txt
.github/workflows/monitor.yml  the 5-minute schedule
.env.example                 variable names for local testing
```

## Delivery: the Claude routine (default)

No secrets are required. The Action commits `alerts/recent.json`; a scheduled
Claude routine (claude.ai → Code → Routines) clones this repo every hour,
reads that file, and sends you a notification with anything new. The routine's
prompt lives in [`ROUTINE_PROMPT.md`](ROUTINE_PROMPT.md) so it can be edited
or recreated.

## Optional: email and text delivery

Add these secrets only if you also want immediate email/text alerts
(Settings → Secrets and variables → Actions → New repository secret):

| Secret | Value |
|---|---|
| `GMAIL_ADDRESS` | The Gmail account that sends alerts |
| `GMAIL_APP_PASSWORD` | A 16-character Gmail **App Password** (not your normal password). Google Account → Security → 2-Step Verification must be on → App passwords |
| `ALERT_EMAIL_TO` | Where alerts go. Comma-separate for more than one |
| `ALERT_SMS_TO` | Your carrier's email-to-text address, e.g. `5551234567@vtext.com` (Verizon), `@txt.att.net` (AT&T), `@tmomail.net` (T-Mobile), `@msg.fi.google.com` (Google Fi). Leave out to disable texts |

Optional, only when you switch texts to Twilio: set `SMS_PROVIDER` to `twilio`
and add `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_FROM`, `TWILIO_TO`.
Nothing else changes.

## First run

The first run with no `seen.json` is a **bootstrap**: it records everything
currently in the feeds as already seen and alerts nothing (it also sends one
`[INIT]` email if email is configured). Real alerts begin on the second run.
This prevents a flood of old items when you turn it on.

To trigger a run by hand: Actions → monitor → Run workflow. Tick *Dry run* to
print instead of send, or *Send the Moderate digest now* to flush the digest.

## Running locally

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python monitor.py --dry-run --state seen.local.json
```

`--dry-run` prints every email and text to the terminal instead of sending.
Export the variables from `.env.example` to send for real.

## Tuning

Everything is in `config.py`:

* `LOOKBACK_HOURS` (24): ignore feed items older than this.
* `MAX_IMMEDIATE_PER_RUN` (10): safety cap on texts per run. Overflow goes to the digest.
* `DIGEST_INTERVAL_HOURS` (6).
* `NWS_HIGH_EVENTS` / `NWS_MODERATE_EVENTS`: which Severe weather events page you, which go to the digest. Everything else at Severe is logged only. Extreme is always Critical.
* `CRITICAL_TERMS`, `HIGH_TERMS`, `AFTERMATH_TERMS`: keyword severity rules.
* `CREDIBLE_DOMAINS`: outlets whose single report counts as credible.
* `INFRA_TERMS`, `CYBER_TERMS`, `IRAN_TERMS`, `US_TERMS`: relevance filter.

## Known limits of v1

* AP and Reuters no longer publish public RSS, so those feeds come from Google
  News site-restricted searches, with Bing News as a fallback when Google
  returns 503 to GitHub's IPs. Google links go through a redirect; Bing links
  are unwrapped to the original article. Entries not actually from the outlet
  are dropped.
* state.gov refuses GitHub runner IPs (HTTP 405), so on Actions the State
  Department feed usually arrives through the Google News or Bing index of
  state.gov. Items are still tagged Confirmed because they are state.gov pages.
* GDELT was dropped in favour of a Google News topic feed: its free API
  rate-limits GitHub's shared IPs on nearly every call.
* NWS issues a new alert ID for each update of an ongoing warning, so a
  long-running warning may be reported more than once.
* GitHub Actions cron is best-effort. Runs may be delayed several minutes or
  occasionally skipped under load.
* GitHub pauses scheduled workflows in a repository with no commits for 60
  days. The bot's `seen.json` commits count as activity, so this should not
  trigger, but if alerts ever stop, check the Actions tab for a disabled
  workflow and click Enable.

## External trigger (backup for GitHub's scheduler)

GitHub's built-in `schedule` trigger is best-effort and, on this repo, did not
fire at all for the first several hours. As a backup, a free external cron
service calls GitHub's "run workflow" API every 5 minutes. Both triggers can
coexist; the `concurrency` block stops them from overlapping.

The call the external service makes:

```
POST https://api.github.com/repos/sekautomationgroup-max/us-infra-cyber-monitor/actions/workflows/monitor.yml/dispatches
Authorization: Bearer <fine-grained personal access token>
Accept: application/vnd.github+json
X-GitHub-Api-Version: 2022-11-28
Content-Type: application/json

{"ref":"main"}
```

GitHub answers `204 No Content` when accepted. The token needs access to this
one repository only, with the **Actions: Read and write** permission. Set an
expiry reminder: fine-grained tokens expire after at most one year.

Setup on cron-job.org: create a job, paste the URL above, set the schedule to
every 5 minutes, choose request method POST, add the three headers, set the
request body to `{"ref":"main"}`, and save. Runs then appear in the Actions
tab labelled `workflow_dispatch`.

## Why a public repo

Public repositories get unlimited GitHub Actions minutes. A private repo on the
free plan gets 2,000 minutes per month; at roughly one minute per run, every
5 minutes, this monitor would use about 8,600 minutes per month and stop
mid-month. Nothing sensitive is in the repo: secrets are stored in GitHub
Secrets, and `seen.json` only holds item IDs, titles and timestamps of public
news.

## Later (not in v1)

X reporter watch list, Bluesky feeds, Claude summaries, full server dashboard.

# Lookout Threat Feed Manager

A Flask web app for managing [Lookout Mobile Endpoint Security](https://www.lookout.com) threat feed blocklists via the [Threat Feed Management API](https://api.lookout.com/mgmt/threat-feeds/api-docs/external).

> **Audience:** Lookout administrators who need to manage custom domain blocklists without using the CLI.

## Features

- **List, create, edit, and delete** threat feeds
- **Search** domains within a feed (client-side filtering via DataTables)
- **Bulk add or delete** domains by pasting a list (up to 15,000 per request)
- **File upload** — CSV or JSON, incremental or full-overwrite mode
- Displays partial-success errors returned by the API per domain

## Requirements

- Python 3.9+
- A Lookout API key with threat feed permissions

## Quick Start

```bash
# 1. Clone
git clone https://github.com/fgravato/web-lookoutthreatfeed.git
cd web-lookoutthreatfeed

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your API key
cp config.ini config.local.ini
# Open config.local.ini and replace YOUR_API_KEY_HERE with your Lookout API key
```

```bash
# 5. Run
flask run
```

Open [http://localhost:5000](http://localhost:5000).

## Configuration

API credentials are read from INI files. `config.local.ini` takes precedence and is git-ignored — put your real key there.

| File | Committed | Purpose |
|---|---|---|
| `config.ini` | Yes | Placeholder template — safe to commit |
| `config.local.ini` | **No** | Your real API key — never commit this |

```ini
[lookout]
api_key = <your-api-key>
```

The API key is exchanged for a short-lived OAuth2 bearer token on first request. The token is cached in the Flask session and refreshed automatically when it expires.

## Usage

### Managing Feeds

The home page lists all feeds for your tenant. From there you can:

- **Create** a new feed (title and description required, 8–255 characters each)
- **Edit** a feed's title, description, or analysis permission
- **Delete** a feed (confirmation prompt)
- **Click a feed** to open its domain management page

### Managing Domains

On the feed detail page:

| Operation | How |
|---|---|
| Search | Type in the search box — filters the domain list instantly |
| Add domains | Paste one domain per line into **Bulk Add**, click Add |
| Delete domains | Paste one domain per line into **Bulk Delete**, click Delete |
| Delete single domain | Click the **×** button next to any domain row |
| Upload file | Choose a CSV or JSON file, select upload type, click Upload |

Bulk add/delete supports up to **15,000 domains per request** (API limit).

### File Upload Formats

#### Incremental CSV — add or remove specific domains

```csv
domain,action
evil.com,add
old-threat.net,delete
```

#### Overwrite CSV — replace the entire feed

```csv
domain
evil.com
bad-actor.net
```

#### JSON — incremental only

```json
{
  "operations": [
    {"domain": "evil.com", "action": "add"},
    {"domain": "old-threat.net", "action": "delete"}
  ]
}
```

File size limits enforced by the API: **7 MB** for file uploads, **2 MB** for JSON incremental updates.

## Running Tests

```bash
source .venv/bin/activate
python -m pytest test_app.py -v
```

Tests use a stub `requests` module — no network calls, no API key required.

## Production Deployment

For anything beyond local use, run behind a WSGI server and set a fixed secret key:

```bash
pip install gunicorn
FLASK_SECRET_KEY=<random-secret> gunicorn app:app
```

Set `app.secret_key` from an environment variable or secrets manager rather than the auto-generated value in `app.py`.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| "Could not authenticate" on home page | API key missing or wrong | Check `config.local.ini` exists and key is correct |
| 401 on every request | Token exchange failing | Verify key has threat feed scopes in the Lookout console |
| Upload returns 413 | File exceeds API size limit | Split into smaller files (7 MB / 2 MB limits) |
| "Invalid Domain" errors after upload | Domain format rejected by API | Ensure domains are bare hostnames (`evil.com`, not `https://evil.com`) |
| Feed not found (404) | Feed ID no longer exists | Refresh the feed list from the home page |

## Project Structure

```
app.py                  # Flask application (~220 lines)
templates/
  base.html             # Bootstrap 5 layout, flash messages
  feeds.html            # Feed list + create modal
  feed_detail.html      # Domain table, bulk ops, file upload, edit modal
config.ini              # API key template (commit-safe placeholder)
requirements.txt        # flask, requests
test_app.py             # 21 unit tests (no network)
swagger.json            # Lookout API OpenAPI 3.0 spec
```

## API Reference

This app wraps the Lookout Threat Feed Management API (`https://api.lookout.com/mgmt/threat-feeds`):

| Method | Path | Purpose |
|---|---|---|
| GET | `/api/v1/threat-feeds` | List feed GUIDs for tenant |
| POST | `/api/v1/threat-feeds` | Create a new feed |
| GET | `/api/v1/threat-feeds/{id}` | Get feed metadata |
| PUT | `/api/v1/threat-feeds/{id}` | Update title / description / analysis flag |
| DELETE | `/api/v1/threat-feeds/{id}` | Delete a feed |
| GET | `/api/v1/threat-feeds/{id}/elements` | Download all domains (CSV) |
| POST | `/api/v1/threat-feeds/{id}/elements` | Upload domains via CSV file |
| POST | `/api/v1/threat-feeds/{id}/elements/incremental-updates` | Bulk add/delete via JSON |

Full spec: [`swagger.json`](swagger.json) or the [live API docs](https://api.lookout.com/mgmt/threat-feeds/api-docs/external).

## Contributing

1. Fork the repo and create a branch
2. Make changes and add tests (`test_app.py`)
3. Run `python -m pytest test_app.py -v` — all tests must pass
4. Open a pull request

## License

MIT

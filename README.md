# Lookout Threat Feed Manager

A Flask web app for managing [Lookout Mobile Endpoint Security](https://www.lookout.com) threat feed blocklists via the [Threat Feed Management API](https://api.lookout.com/mgmt/threat-feeds/api-docs/external).

## Features

- **List, create, edit, and delete** threat feeds
- **Search** domains within a feed
- **Bulk add or delete** domains by pasting a list (up to 15,000 per request)
- **File upload** — CSV or JSON, incremental or overwrite mode
- Displays partial-success errors returned by the API

## Requirements

- Python 3.9+
- A Lookout API key with threat feed permissions

## Setup

```bash
# 1. Clone
git clone https://github.com/fgravato/web-lookoutthreatfeed.git
cd web-lookoutthreatfeed

# 2. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure your API key
cp config.ini config.local.ini
# Edit config.local.ini and replace YOUR_API_KEY_HERE with your key
```

`config.local.ini` is git-ignored and takes precedence over `config.ini`.

## Running

```bash
source .venv/bin/activate
flask run
```

Open [http://localhost:5000](http://localhost:5000) in your browser.

For production use, run behind a WSGI server (e.g. `gunicorn app:app`).

## Configuration

| File | Purpose |
|---|---|
| `config.ini` | Template — commit-safe placeholder |
| `config.local.ini` | Your real API key — **never commit this** |

Both files use INI format:

```ini
[lookout]
api_key = <your-api-key>
```

## File Upload Formats

### Incremental CSV (`uploadType=INCREMENTAL`)

Adds or removes specific domains without affecting the rest of the feed.

```csv
domain,action
evil.com,add
old-threat.net,delete
```

### Overwrite CSV (`uploadType=OVERWRITE`)

Replaces the entire feed with the provided list.

```csv
domain
evil.com
bad-actor.net
```

### JSON (incremental only)

```json
{
  "operations": [
    {"domain": "evil.com", "action": "add"},
    {"domain": "old-threat.net", "action": "delete"}
  ]
}
```

## Running Tests

```bash
source .venv/bin/activate
python -m pytest test_app.py -v
```

## Project Structure

```
app.py                  # Flask application
templates/
  base.html             # Bootstrap 5 layout
  feeds.html            # Feed list and create form
  feed_detail.html      # Domain table, bulk ops, file upload
config.ini              # API key template (commit-safe)
requirements.txt
test_app.py             # Unit tests (no network calls)
swagger.json            # Lookout API OpenAPI spec
```

## API Reference

This app wraps the following Lookout API endpoints:

| Method | Endpoint | Purpose |
|---|---|---|
| GET | `/api/v1/threat-feeds` | List feed GUIDs |
| POST | `/api/v1/threat-feeds` | Create feed |
| GET | `/api/v1/threat-feeds/{id}` | Get feed metadata |
| PUT | `/api/v1/threat-feeds/{id}` | Update feed metadata |
| DELETE | `/api/v1/threat-feeds/{id}` | Delete feed |
| GET | `/api/v1/threat-feeds/{id}/elements` | Download domains (CSV) |
| POST | `/api/v1/threat-feeds/{id}/elements` | Upload domains (CSV file) |
| POST | `/api/v1/threat-feeds/{id}/elements/incremental-updates` | Bulk add/delete (JSON) |

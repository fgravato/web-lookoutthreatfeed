import configparser
import csv
import io
import json
import os
import time

import requests
from flask import (Flask, flash, redirect, render_template, request,
                   session, url_for)

app = Flask(__name__)
app.secret_key = os.urandom(24)

BASE_URL = "https://api.lookout.com/mgmt/threat-feeds/api/v1"
TOKEN_URL = "https://api.lookout.com/oauth2/token"


def load_api_key():
    cfg = configparser.ConfigParser()
    for name in ("config.local.ini", "config.ini"):
        if os.path.exists(name):
            cfg.read(name)
            return cfg.get("lookout", "api_key", fallback=None)
    return None


def get_token():
    """Return a cached bearer token, refreshing if expired."""
    if "token" in session and session.get("token_exp", 0) > time.time() + 30:
        return session["token"]

    api_key = load_api_key()
    if not api_key:
        return None

    resp = requests.post(
        TOKEN_URL,
        headers={"Authorization": f"Bearer {api_key}",
                 "Content-Type": "application/x-www-form-urlencoded"},
        data={"grant_type": "client_credentials"},
        timeout=10,
    )
    if resp.status_code != 200:
        return None

    data = resp.json()
    session["token"] = data["access_token"]
    session["token_exp"] = time.time() + data.get("expires_in", 3600)
    return session["token"]


def auth_headers(extra=None):
    h = {"Authorization": f"Bearer {get_token()}", "Accept": "application/json"}
    if extra:
        h.update(extra)
    return h


def api_error(resp):
    try:
        detail = resp.json().get("detail") or resp.json().get("title") or resp.text
    except Exception:
        detail = resp.text
    return detail or f"HTTP {resp.status_code}"


# ── Feed routes ──────────────────────────────────────────────────────────────

@app.route("/")
def index():
    token = get_token()
    if not token:
        flash("Could not authenticate. Check your config.ini API key.", "danger")
        return render_template("feeds.html", feeds=[])

    resp = requests.get(f"{BASE_URL}/threat-feeds", headers=auth_headers(), timeout=10)
    if resp.status_code != 200:
        flash(f"Failed to list feeds: {api_error(resp)}", "danger")
        return render_template("feeds.html", feeds=[])

    guids = resp.json()
    feeds = []
    for guid in guids:
        m = requests.get(f"{BASE_URL}/threat-feeds/{guid}", headers=auth_headers(), timeout=10)
        if m.status_code == 200:
            feeds.append(m.json())

    return render_template("feeds.html", feeds=feeds)


@app.route("/feeds/create", methods=["POST"])
def create_feed():
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    allow_analysis = request.form.get("allowAnalysis") == "on"

    errors = []
    if not (8 <= len(title) <= 255):
        errors.append("Title must be 8–255 characters.")
    if description and not (8 <= len(description) <= 255):
        errors.append("Description must be 8–255 characters.")
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("index"))

    payload = {"feedType": "CSV", "title": title, "description": description,
               "allowAnalysis": allow_analysis}
    resp = requests.post(f"{BASE_URL}/threat-feeds",
                         headers=auth_headers({"Content-Type": "application/json"}),
                         json=payload, timeout=10)
    if resp.status_code == 201:
        flash(f"Feed created (ID: {resp.json()['feedId']})", "success")
    else:
        flash(f"Failed to create feed: {api_error(resp)}", "danger")

    return redirect(url_for("index"))


@app.route("/feeds/<feed_id>")
def feed_detail(feed_id):
    token = get_token()
    if not token:
        flash("Authentication error.", "danger")
        return redirect(url_for("index"))

    m = requests.get(f"{BASE_URL}/threat-feeds/{feed_id}", headers=auth_headers(), timeout=10)
    if m.status_code != 200:
        flash(f"Feed not found: {api_error(m)}", "danger")
        return redirect(url_for("index"))

    metadata = m.json()

    # Download domains
    d = requests.get(f"{BASE_URL}/threat-feeds/{feed_id}/elements",
                     headers={**auth_headers(), "Accept": "text/csv"}, timeout=30)
    domains = []
    if d.status_code == 200 and d.text.strip():
        reader = csv.reader(io.StringIO(d.text))
        for row in reader:
            if row and row[0].lower() != "domain":
                domains.append(row[0].strip())

    search = request.args.get("q", "").lower()
    if search:
        domains = [dom for dom in domains if search in dom.lower()]

    return render_template("feed_detail.html", feed=metadata, domains=domains,
                           search=search, total=len(domains))


@app.route("/feeds/<feed_id>/update", methods=["POST"])
def update_feed(feed_id):
    title = request.form.get("title", "").strip()
    description = request.form.get("description", "").strip()
    allow_analysis = request.form.get("allowAnalysis") == "on"

    errors = []
    if title and not (8 <= len(title) <= 255):
        errors.append("Title must be 8–255 characters.")
    if description and not (8 <= len(description) <= 255):
        errors.append("Description must be 8–255 characters.")
    if errors:
        for e in errors:
            flash(e, "danger")
        return redirect(url_for("feed_detail", feed_id=feed_id))

    payload = {}
    if title:
        payload["title"] = title
    if description:
        payload["description"] = description
    payload["allowAnalysis"] = allow_analysis

    resp = requests.put(f"{BASE_URL}/threat-feeds/{feed_id}",
                        headers=auth_headers({"Content-Type": "application/json"}),
                        json=payload, timeout=10)
    if resp.status_code == 200:
        flash("Feed updated.", "success")
    else:
        flash(f"Update failed: {api_error(resp)}", "danger")

    return redirect(url_for("feed_detail", feed_id=feed_id))


@app.route("/feeds/<feed_id>/delete", methods=["POST"])
def delete_feed(feed_id):
    resp = requests.delete(f"{BASE_URL}/threat-feeds/{feed_id}",
                           headers=auth_headers(), timeout=10)
    if resp.status_code == 200:
        flash("Feed deleted.", "success")
    else:
        flash(f"Delete failed: {api_error(resp)}", "danger")
    return redirect(url_for("index"))


# ── Domain operations ─────────────────────────────────────────────────────────

def _incremental_update(feed_id, operations):
    """POST incremental update; return list of error dicts (empty = full success)."""
    resp = requests.post(
        f"{BASE_URL}/threat-feeds/{feed_id}/elements/incremental-updates",
        headers=auth_headers({"Content-Type": "application/json"}),
        json={"operations": operations},
        timeout=30,
    )
    if resp.status_code == 200:
        return resp.json().get("errors", [])
    return [{"errorMessage": api_error(resp)}]


@app.route("/feeds/<feed_id>/domains/add", methods=["POST"])
def add_domains(feed_id):
    raw = request.form.get("domains", "").strip()
    if not raw:
        flash("No domains provided.", "warning")
        return redirect(url_for("feed_detail", feed_id=feed_id))

    domains = [line.strip() for line in raw.splitlines() if line.strip()]
    if len(domains) > 15000:
        flash("Maximum 15,000 domains per request.", "danger")
        return redirect(url_for("feed_detail", feed_id=feed_id))

    ops = [{"domain": d, "action": "add"} for d in domains]
    errors = _incremental_update(feed_id, ops)
    if not errors:
        flash(f"Added {len(domains)} domain(s).", "success")
    else:
        flash(f"Completed with {len(errors)} error(s). See details below.", "warning")
        session["last_errors"] = errors

    return redirect(url_for("feed_detail", feed_id=feed_id))


@app.route("/feeds/<feed_id>/domains/delete", methods=["POST"])
def delete_domains(feed_id):
    raw = request.form.get("domains", "").strip()
    if not raw:
        flash("No domains provided.", "warning")
        return redirect(url_for("feed_detail", feed_id=feed_id))

    domains = [line.strip() for line in raw.splitlines() if line.strip()]
    ops = [{"domain": d, "action": "delete"} for d in domains]
    errors = _incremental_update(feed_id, ops)
    if not errors:
        flash(f"Deleted {len(domains)} domain(s).", "success")
    else:
        flash(f"Completed with {len(errors)} error(s).", "warning")
        session["last_errors"] = errors

    return redirect(url_for("feed_detail", feed_id=feed_id))


@app.route("/feeds/<feed_id>/domains/upload", methods=["POST"])
def upload_domains(feed_id):
    upload_type = request.form.get("uploadType", "INCREMENTAL")
    file = request.files.get("file")

    if not file or not file.filename:
        flash("No file selected.", "warning")
        return redirect(url_for("feed_detail", feed_id=feed_id))

    filename = file.filename.lower()
    content = file.read()

    if filename.endswith(".json"):
        try:
            data = json.loads(content)
            # Accept {"operations": [...]} or a plain list
            ops = data if isinstance(data, list) else data.get("operations", [])
        except json.JSONDecodeError as e:
            flash(f"Invalid JSON: {e}", "danger")
            return redirect(url_for("feed_detail", feed_id=feed_id))

        errors = _incremental_update(feed_id, ops)
        if not errors:
            flash(f"Processed {len(ops)} operation(s).", "success")
        else:
            flash(f"Completed with {len(errors)} error(s).", "warning")
            session["last_errors"] = errors

    elif filename.endswith(".csv"):
        resp = requests.post(
            f"{BASE_URL}/threat-feeds/{feed_id}/elements?uploadType={upload_type}",
            headers={"Authorization": f"Bearer {get_token()}"},
            files={"file": (file.filename, content, "text/csv")},
            timeout=60,
        )
        if resp.status_code == 200:
            # Parse response CSV for errors
            errors = []
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                if row.get("ERROR_CODE"):
                    errors.append(row)
            if not errors:
                flash("Upload successful.", "success")
            else:
                flash(f"Upload completed with {len(errors)} error(s).", "warning")
                session["last_errors"] = errors
        else:
            flash(f"Upload failed: {api_error(resp)}", "danger")
    else:
        flash("Only .csv and .json files are supported.", "danger")

    return redirect(url_for("feed_detail", feed_id=feed_id))


if __name__ == "__main__":
    app.run(debug=True)

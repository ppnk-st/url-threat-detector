# URL Threat Detector

A Flask web app that analyzes URLs for common phishing and malware warning signs. It combines local heuristic rules, a configurable domain blocklist, and an optional Google Safe Browsing lookup.

> **Live demo:** [Open URL Threat Detector](https://url-threat-detector-udjc.onrender.com)

## Features

- Scores URLs from 0 to 100 and groups results by risk level.
- Checks for suspicious URL patterns, including IP hosts, misleading credentials, suspicious domains, brand impersonation, and embedded links.
- Optionally checks URLs with Google Safe Browsing.
- Saves scan results to a local SQLite history.
- Provides both a web interface and a JSON API.

## Run locally

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open <http://127.0.0.1:8080>.

To enable Google Safe Browsing, create a `.env` file in the project root:

```env
SECRET_KEY=replace-with-a-random-secret
SAFE_BROWSING_API_KEY=your-api-key
```

Keep `.env` private; it is ignored by Git. Without the Google key, local rules and the blocklist still run.

## Deploy

This Flask app needs a Python web host; GitHub Pages only serves static sites. For Render, create a **Web Service** connected to this repository and use:

- **Build command:** `pip install -r requirements.txt`
- **Start command:** `gunicorn app:app --bind 0.0.0.0:$PORT`

Set `SAFE_BROWSING_API_KEY` and `SECRET_KEY` in the host’s environment-variable settings. Never commit secrets to GitHub. The app uses SQLite for history, so data may not persist on hosts with an ephemeral filesystem.

## API

`POST /api/scan` accepts JSON and returns a scan report:

```json
{"url": "https://example.com/login"}
```

## Tests

```bash
python -m pytest -q
```

## Limitations

Risk scores are heuristic and cannot guarantee that a URL is safe. Google Safe Browsing v4 is deprecated; commercial use should use Google Web Risk.

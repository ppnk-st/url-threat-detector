# URL Threat Detector

## Run locally

```bash
source .venv/bin/activate
python app.py
```

Open <http://127.0.0.1:8080>. The app uses port 8080 by default; set `PORT` to override it.

## Google Safe Browsing lookup

The app reads `SAFE_BROWSING_API_KEY` from `.env` at startup. Put your Google Safe Browsing API key in that variable to enable the lookup; leave it empty to use only the local rules and blocklist. Keep `.env` private and do not commit it.

The configured lookup uses Google's Safe Browsing v4 endpoint. Google marks v4 as deprecated, so this integration may stop working if Google disables the endpoint. Commercial use should use Google Web Risk instead.


# Mail Vault — FULL SIH 26159 Prototype

This build is designed around the complete SIH 26159 deliverables rather than a static mockup.

## Included

1. Passive PCAP upload and analysis.
2. SMTP / IMAP / POP3 identification using TCP ports plus payload evidence.
3. TCP stream grouping and payload reconstruction.
4. STARTTLS detection.
5. TLS record/handshake parsing for common ClientHello/ServerHello/Certificate structures.
6. TLS version extraction.
7. Cipher suite extraction.
8. Key-exchange / forward-secrecy assessment.
9. X.509 DER certificate extraction and parsing.
10. Certificate validity/expiration/public-key/signature observations.
11. Weak/deprecated cryptography findings.
12. Deterministic cryptographic posture scoring.
13. ML anomaly detection with IsolationForest when enough sessions are present.
14. Prioritized findings and remediation recommendations.
15. Interactive SOC-style dashboard.
16. JSON export.
17. HTML forensic report export.
18. Real PDF report export using ReportLab.
19. Demo dataset so the UI works before a PCAP is supplied.
20. Render deployment configuration.

## Run locally

From the project folder, create and activate a virtual environment:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r backend/requirements.txt
```

Start the API in Terminal 1:

```bash
uvicorn backend.main:app --reload --port 8000
```

Start the frontend in Terminal 2:

```bash
cd frontend
python3 -m http.server 5173
```

Open:

http://localhost:5173

The frontend calls the backend at `http://localhost:8000/api`.

On Windows PowerShell, use `.venv\Scripts\python.exe` and `.venv\Scripts\Activate.ps1` instead of the Unix commands above.

## One-command-ish development

Terminal 1:
`uvicorn backend.main:app --reload --port 8000`

Terminal 2:
`cd frontend && python3 -m http.server 5173`

## PCAP support

Upload `.pcap` or `.pcapng`.

The parser groups TCP packets into bidirectional streams and examines the reconstructed payload for:
- SMTP / IMAP / POP3
- STARTTLS
- TLS records
- ServerHello
- Certificate handshake messages
- cipher suites
- negotiated TLS versions
- certificate properties

For production-grade broad protocol coverage, deploy with a recent TShark/Zeek sidecar and add their richer parsers. This prototype intentionally keeps a Python-only baseline so it is easy to demonstrate and extend.

## ML

The ML layer uses IsolationForest on cryptographic/session features:
- TLS version
- forward secrecy
- STARTTLS behavior
- deterministic security score
- certificate count

It is not presented as a replacement for forensic evidence; it is an anomaly-prioritization layer.

## Important evidence limitation

A passive PCAP analyzer cannot prove that an active MITM/downgrade attack occurred merely because a weak negotiation appears. The UI therefore reports observable evidence and risk, not an unqualified claim of compromise.

## Deployment

### Vercel

The repository includes `vercel.json` and `api/index.py` for a single Vercel project:

- `api/index.py` exposes the FastAPI application as a Vercel Python function.
- `/api/*` is routed to FastAPI.
- All other paths are routed to the static frontend in `frontend/`.
- Root `requirements.txt` includes the backend dependencies for Vercel's build.

Deploy from the Vercel dashboard:

1. Push this repository to GitHub.
2. Open [vercel.com](https://vercel.com) and sign in.
3. Select **Add New Project**, then import `Ozair-aly/sih26159`.
4. Keep the repository root as the project root.
5. Leave the framework preset as **Other** and keep the default build command empty.
6. Click **Deploy**.
7. Open the generated URL and verify the dashboard loads.
8. Verify the API with `https://YOUR-VERCEL-DOMAIN/api/health` and the interactive docs at `https://YOUR-VERCEL-DOMAIN/docs`.

No environment variables are required for the current prototype. Do not commit API keys, tokens, captures containing sensitive data, or local virtual environments. PCAP uploads are processed in the serverless request and should be treated as sensitive evidence.

The Vercel function has serverless execution and upload-size limits. For large captures, long-running analysis, or production evidence retention, use the included Render configuration or a dedicated backend service and point the frontend `API` constant at that backend.

### GitHub workflow

From the project folder, configure the supplied remote and push changes:

```bash
git init
git remote add origin https://github.com/Ozair-aly/sih26159.git
git add .
git commit -m "Prepare Mail Vault for Vercel deployment"
git branch -M main
git push -u origin main
```

If `origin` already exists, use `git remote set-url origin https://github.com/Ozair-aly/sih26159.git` instead of adding it. GitHub may request browser authentication or a personal access token; never place the token in this README or in source files.

For future updates:

```bash
git add .
git commit -m "Describe the change"
git push
```

When the GitHub repository is connected to Vercel, each push to `main` creates a new production deployment and pull requests receive preview deployments.

### Render alternative

`render.yaml` is included for Render. It deploys the FastAPI backend as a Python web service. The frontend can be hosted separately as a static site, or served behind the same backend after adding a static-file mount.

### Deployment checklist

- Confirm the GitHub repository contains `api/index.py`, `vercel.json`, and root `requirements.txt`.
- Confirm the Vercel deployment returns HTTP 200 for `/` and `/docs`.
- Upload a small test PCAP and confirm the analysis result appears.
- Test JSON, HTML, and PDF report downloads.
- Review Vercel function logs if an upload fails.
- Rotate or remove any credentials accidentally included in a capture before sharing it.

## Production additions for a final SIH build

- TShark/Zeek deep protocol parsing.
- Full TLS 1.3 encrypted-handshake metadata handling where observable.
- Complete certificate-chain trust validation against a selected enterprise/root store.
- Configurable crypto policy profiles (enterprise / government / custom).
- Persistent case management and evidence hashes.
- Authentication and analyst roles.
- Larger labeled PCAP corpus and measured ML precision/recall.
- Immutable evidence logging if blockchain is required by the theme.

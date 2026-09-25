# ForensicChain — Frontend

React-based UI for the Cryptographically Verifiable Digital Forensics system.
Connects to the FastAPI backend built in Phase 3.

---

## Files

```
forensics-frontend/
├── index.html          ← Complete single-file app (open directly in browser)
├── src/
│   └── api.js          ← API client — every endpoint wired to the backend
└── README.md
```

---

## Running in demo mode (no backend needed)

Just open `index.html` in a browser. All data is local mock data.
Every API call falls back silently when the backend is unreachable.

```bash
open forensics-frontend/index.html
# or
python3 -m http.server 3000 --directory forensics-frontend
# then open http://localhost:3000
```

---

## Running against the live backend

1. Start the backend: `docker compose up -d` (from the `forensics-api` folder)
2. Open `index.html` — the app auto-connects to `http://localhost:8000/api/v1`
3. Log in with a real account created by the admin

The `src/api.js` module can be imported into a React project:
```bash
npx create-react-app forensics-ui
cp src/api.js forensics-ui/src/api.js
# Then import functions from './api' in your components
```

---

## Screens and roles

| Screen | URL path | Visible to |
|---|---|---|
| Dashboard | `/` | All roles |
| Cases | `/cases` | All roles |
| Case detail | `/cases/:id` | All roles (assigned users only) |
| Evidence registry | `/evidence` | CaseManager, LabTechnician, Examiner, Admin |
| Chain of custody | `/custody` | All roles |
| Tasks | `/tasks` | CaseManager, Examiner |
| Task detail + findings | `/tasks/:id` | CaseManager, Examiner |
| Reports | `/reports` | Examiner, LegalReviewer, CaseManager |
| Report versions | `/reports/:id` | Examiner, LegalReviewer, CaseManager |
| Verify hash (public) | `/verify` | All — no login required |
| Users | `/users` | Admin only |
| Audit log | `/audit` | Admin only |

---

## Role behaviour

Each role sees a different subset of the navigation and different actions:

**Case Manager**
- Opens cases, assigns lab techs and examiners, changes case status
- Assigns analysis tasks to examiners
- Submits reports to legal review

**Lab Technician**
- Registers evidence (file upload → SHA-256 computed server-side)
- Imports acquisition hashes from Autopsy/FTK CSV
- Initiates custody transfers

**Examiner**
- Accepts custody transfers
- Views evidence with live integrity check
- Creates tasks progress (in progress → completed)
- Records findings against tasks
- Writes and versions forensic reports

**Legal Reviewer**
- Accepts custody transfers from examiners
- Reviews and locks reports as court-ready
- Downloads verifiable court PDF

**Admin**
- Manages all user accounts and roles
- Views the full immutable audit log with filtering and CSV export
- Cannot modify evidence, custody records, or report versions

**Public Verifier**
- No login needed
- Submits a SHA-256 hash to the verification portal
- Gets back: integrity status, first registered date, custody transfer count

---

## Key UI decisions

**Hash pills** — all SHA-256 values are displayed in a distinct monospace
pill (`JetBrains Mono`). Truncated in tables, full 64-char display in
detail views and the verification result. Never confused with regular text.

**Tamper alerts** — rows with `integrity_status: tampered` are highlighted
in red in the evidence table. A critical alert card appears on the dashboard.

**Custody timeline** — the chain of custody is shown as a vertical timeline
with coloured dots (green = accepted, amber = pending, red = rejected).
Gap detection: if evidence had no custodian for >60 seconds between transfers,
a warning bar appears.

**Report versioning** — every version is listed in a table with its
content hash, author, and change summary. Court-ready versions show a
lock icon and cannot be edited. The diff tab shows a unified diff between
any two versions.

**Role-gated actions** — buttons and forms are hidden (not just disabled)
for roles that don't have permission. This mirrors the backend's RBAC checks.

---

## Connecting to a production backend

Update the API base URL in `src/api.js`:

```js
const BASE = process.env.REACT_APP_API_URL || 'https://forensics.yourdomain.com/api/v1';
```

Or set `REACT_APP_API_URL` in your `.env` file before building.

For the single-file `index.html` version, update line 6:

```js
const API = 'https://forensics.yourdomain.com/api/v1';
```

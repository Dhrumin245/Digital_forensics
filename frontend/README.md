# ForensicChain Frontend

React + TypeScript UI for the ForensicChain FastAPI backend. The client uses live API responses and never falls back to mock data.

## Run locally

Start the backend and its database first:

```bash
cd ../backend
docker compose up -d
```

Then start the frontend:

```bash
cd ../frontend
npm install
npm run dev
```

Open the Vite URL shown in the terminal. The Vite development server proxies `/api` to `http://localhost:8000`, so requests continue through FastAPI to PostgreSQL and the configured storage services. Set `VITE_API_URL` when the API is hosted elsewhere.

## Connected workflows

The current UI wires these database-backed flows:

- Authenticated login and current-user profile loading
- Accessible case listing and case creation for Case Managers
- Case selection and evidence registry loading
- Lab Technician evidence upload with server-side SHA-256 hashing
- Public hash verification without authentication

API errors are shown in the interface. The browser does not generate sample records.

## Build

```bash
npm run build
```

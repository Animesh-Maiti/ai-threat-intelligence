# AI Threat Intelligence

AI-assisted threat intelligence monorepo for URL, TLS, scam, and HTTP header analysis.

## Layout

- `backend/`: FastAPI analysis service
- `frontend/`: Next.js application
- `contracts/`: Hardhat smart contracts
- `docs/`: Architecture and test documentation

## Deployment configuration

- Deploy the FastAPI service from `backend/`; its `Procfile` reads the platform-provided `PORT`.
- Set backend `ALLOWED_ORIGINS` to a comma-separated list of frontend origins. The default allows localhost development and `https://*.vercel.app`.
- Set the Vercel build environment variable `NEXT_PUBLIC_API_URL` to the backend origin (for example, `https://your-backend-service.onrender.com`). The frontend appends `/api/v1`.
- Copy `backend/.env.example` and `frontend/.env.example` for local configuration. Do not commit environment files containing credentials.

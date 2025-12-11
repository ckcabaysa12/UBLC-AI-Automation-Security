# UBLC AI Automation Security

Lightweight Flask app with containerized deploy and CI.

## Quickstart (local, no Docker)

```
pip install -r requirements.txt
PORT=5001 python app.py   # or omit PORT if 5000 is free
```

App will run on http://localhost:5001 (or the port you set). Health check: `/health`.

## Docker

Build and run:

```
docker build -t ublc-ai .
docker run --rm -p 5001:5000 --env-file .env ublc-ai
```

Then open http://localhost:5001.

## CI/CD

- GitHub Actions workflow at `.github/workflows/ci.yml`:
  - installs deps
  - syntax check `app.py`
  - builds Docker image
  - if on `main`, pushes image to GHCR at `ghcr.io/<owner>/<repo>:<sha>` and `:latest`
- Requires `GITHUB_TOKEN` (provided automatically) with packages:write (set in the workflow).

## Deploy options

- Use the published GHCR image on a container host (Render, Fly.io, Railway, ECS/Fargate, Azure Web App for Containers, etc.).
- Expose port 5000 in the container; map to any host port you prefer.
- Supply environment variables for OpenAI key, Firebase credentials path/json, SMTP settings, etc.

## Notes

- `.dockerignore` keeps secrets and caches out of the build context.
- `Dockerfile` uses gunicorn on `0.0.0.0:5000`.
- `/health` is available for uptime checks.

# Hacker-trap

A small, privacy-preserving HTTP honeypot built with FastAPI for defensive observation.

## Deploy to Railway

1. Connect this GitHub repository to Railway and deploy the `main` branch.
2. Railway detects `requirements.txt` and uses the `Procfile` web command.
3. Generate a public domain for the service.
4. Check `/health` to confirm the service is running.
5. Inspect Railway runtime logs for JSON event records.

## Events and privacy

The app logs request time, method, path, query parameter names, client address as seen by the app, user-agent, response status, and simple heuristic tags. It intentionally does not read or save submitted form bodies, usernames, or passwords. Treat IP addresses and logs as potentially sensitive; restrict log access and use an appropriate retention period.

## Safety

- This service is a decoy and does not execute submitted commands or uploaded files.
- Do not use it as a proxy or connect it to production systems.
- Before public deployment, keep it isolated, monitor resource usage, and restrict unnecessary outbound traffic.
- The logged client address may represent a proxy rather than the original person.

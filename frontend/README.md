# frontend/ (operations dashboard) — Member 4

React app for FR-7. Talks only to the API described in `docs/api-contract.md`.

Integration notes from the backend:

- **Same origin in development.** Configure the Vite dev server to proxy `/api` to
  `http://127.0.0.1:8000` so cookies and CSRF work without CORS.
- **CSRF.** Call `GET /api/v1/auth/csrf/` once on load, then send the `csrftoken`
  cookie value in an `X-CSRFToken` header on every POST, PUT, PATCH and DELETE.
- **Session cookie** (`fogtrust_session`) is HttpOnly. JavaScript cannot and should not read it.
- **Errors** always look like `{"error": {"code", "message", "request_id"}}`.
  Show `message` to the user and switch on `code` in code. Show `request_id` in
  error toasts so a bug report can be matched to the server log.
- **Never hide a button as the only protection.** The server enforces roles; the UI just mirrors them.

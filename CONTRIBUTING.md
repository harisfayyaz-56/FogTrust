# Contributing to FogTrust

These rules keep four people working in parallel without breaking each other's code, and keep
the Git history readable for review.

## Branches

| Branch | Purpose |
|---|---|
| `main` | Always runs and passes tests. **No direct pushes.** |
| `feature/<slice>-<topic>` | New work, e.g. `feature/m1-audit-log`, `feature/m2-heartbeat-verify` |
| `fix/<topic>` | Bug fixes |
| `docs/<topic>` | Documentation only |

Slice prefixes: `m1` identity/audit, `m2` crypto/simulator, `m3` scheduler/trust, `m4` dashboard/QA.

## Workflow

1. `git switch main && git pull`
2. `git switch -c feature/m1-<topic>`
3. Work in small steps. **Commit each time one thing works.**
4. Run `python -m pytest` before every push.
5. Push and open a pull request. Fill in the template.
6. At least **one teammate reviews** before merging. Use "Squash and merge" only if the branch
   history is messy; otherwise keep the individual commits.
7. Delete the branch after merging.

## Commit messages

Format: `type(scope): short description in the imperative`

| Type | Use for |
|---|---|
| `feat` | New behaviour |
| `fix` | Bug fix |
| `test` | Adding or changing tests only |
| `docs` | Documentation only |
| `refactor` | Code change with no behaviour change |
| `chore` | Tooling, dependencies, config |
| `security` | Hardening that is not a new feature |

Examples:

```
feat(accounts): add role field to custom user model
test(core): check crash responses hide stack traces
docs(api): draft enrollment and revocation endpoints
```

Keep the first line under 72 characters. Add a body when the *why* is not obvious.

## Never commit

- `.env`, private keys, real passwords, tokens, or the SQLite database file
- Generated files (`__pycache__`, `node_modules`, `dist`)

If a secret is committed by mistake: tell the team, **rotate the secret immediately**, then remove
it from history. Deleting it in a new commit is not enough.

## Code rules

- Security logic lives in `engine/` (pure Python) or in backend services, never only in the frontend.
- Every endpoint declares its permission class explicitly, even when it uses the default.
- Raise `APIError(ErrorCode.X)` for expected failures. Add new codes to `backend/core/errors.py`
  and `docs/api-contract.md` together.
- Every new feature comes with at least one positive and one negative test.

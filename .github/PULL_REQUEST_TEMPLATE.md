## Summary

<!-- What does this change do? Link the issue it closes. -->

## Type of change

<!-- Pick one. The PR title MUST follow Conventional Commits
     (feat:, fix:, docs:, test:, refactor:, chore:, ...) so release-please
     can derive the next version. -->

- [ ] feat — new user-visible behavior
- [ ] fix — bug fix
- [ ] docs — documentation only
- [ ] test — tests only
- [ ] refactor / chore — internal change, no behavior delta

## Checklist

- [ ] PR title follows Conventional Commits
- [ ] Tests added or updated (unit and/or live-VL where applicable)
- [ ] `poetry run pytest` passes locally
- [ ] `poetry run ruff check . && poetry run mypy` clean
- [ ] If LogsQL output changed: `docs/mapping.md` updated
- [ ] No homelab IPs, internal hostnames, or personal artefacts introduced

# Q3897: Unscoped `status` webhook (target_url injection) marks the victim commit deployable

## Question
Can an unprivileged attacker who sets `target_url`/`description` to values persisted with the status and later surfaced deliver a `status` webhook that `StatusHandler#process` applies via `Commit.where(sha: params.sha)` with no repository check, so it marks the victim commit deployable on a stack the attacker does not own?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` payload `sha`, `state`, `context`, `description`, `target_url`; attacker sets `target_url`/`description` to values persisted with the status and later surfaced
- Exploit idea: `StatusHandler#process` selects commits by bare SHA across all repositories and calls `create_status_from_github!`, so `Commit#deployable?` becomes true (`success? && !blocked?`)
- Invariant to test: A GitHub status may only alter the CI state of commits in the repository that actually produced the status event.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed two stacks in different repositories sharing a commit SHA, process a crafted status payload, assert the OTHER repository's commit CI state and deployability changed.

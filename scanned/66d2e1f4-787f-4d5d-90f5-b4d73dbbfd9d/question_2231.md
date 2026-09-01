# Q2231: Unscoped `status` webhook (attacker-chosen context) triggers continuous delivery

## Question
Can an unprivileged attacker who sets `context` to the exact required status context the victim stack lists in `ci.require` deliver a `status` webhook that `StatusHandler#process` applies via `Commit.where(sha: params.sha)` with no repository check, so it triggers continuous delivery on a stack the attacker does not own?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` payload `sha`, `state`, `context`, `description`, `target_url`; attacker sets `context` to the exact required status context the victim stack lists in `ci.require`
- Exploit idea: `StatusHandler#process` selects commits by bare SHA across all repositories and calls `create_status_from_github!`, so `Stack#trigger_continuous_delivery` ships the now-green commit
- Invariant to test: A GitHub status may only alter the CI state of commits in the repository that actually produced the status event.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed two stacks in different repositories sharing a commit SHA, process a crafted status payload, assert the OTHER repository's commit CI state and deployability changed.

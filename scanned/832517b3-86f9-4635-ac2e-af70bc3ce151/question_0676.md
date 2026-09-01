# Q0676: Unscoped `status` webhook (empty-tree / cherry-picked shared SHA) marks the victim commit deployable

## Question
Can an unprivileged attacker who creates a commit in the attacker's own repo whose SHA collides with a target tenant's commit SHA (identical tree/parents, e.g. a cherry-pick or empty commit reproduction) deliver a `status` webhook that `StatusHandler#process` applies via `Commit.where(sha: params.sha)` with no repository check, so it marks the victim commit deployable on a stack the attacker does not own?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` payload `sha`, `state`, `context`, `description`, `target_url`; attacker creates a commit in the attacker's own repo whose SHA collides with a target tenant's commit SHA (identical tree/parents, e.g. a cherry-pick or empty commit reproduction)
- Exploit idea: `StatusHandler#process` selects commits by bare SHA across all repositories and calls `create_status_from_github!`, so `Commit#deployable?` becomes true (`success? && !blocked?`)
- Invariant to test: A GitHub status may only alter the CI state of commits in the repository that actually produced the status event.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed two stacks in different repositories sharing a commit SHA, process a crafted status payload, assert the OTHER repository's commit CI state and deployability changed.

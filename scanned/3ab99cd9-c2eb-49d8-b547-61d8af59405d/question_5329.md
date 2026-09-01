# Q5329: [failure] status `buildkite/deploy` on a ignore_ci true stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: buildkite/deploy`, `state: failure`) for a SHA shared with a victim stack where ignore_ci true, so `StatusHandler#process` (no repository scoping) flips the required context and, because `Commit#deployable?` short-circuits CI so any commit is shippable, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: buildkite/deploy`,`state: failure`; victim stack has ignore_ci true
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `ignore_ci true` (`Commit#deployable?` short-circuits CI so any commit is shippable) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `buildkite/deploy` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with ignore_ci true requiring `buildkite/deploy`; process the `failure` status; assert deployability/merge/block changed.

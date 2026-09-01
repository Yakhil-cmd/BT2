# Q3489: [success] status `shipit/checks` on a ignore_ci true stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: shipit/checks`, `state: success`) for a SHA shared with a victim stack where ignore_ci true, so `StatusHandler#process` (no repository scoping) flips the required context and, because `Commit#deployable?` short-circuits CI so any commit is shippable, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: shipit/checks`,`state: success`; victim stack has ignore_ci true
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `ignore_ci true` (`Commit#deployable?` short-circuits CI so any commit is shippable) turns the flip into a `success`-driven ship/block
- Invariant to test: A `shipit/checks` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with ignore_ci true requiring `shipit/checks`; process the `success` status; assert deployability/merge/block changed.

# Q2651: [failure] status `ci/coverage` on a blocking_statuses configured stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: ci/coverage`, `state: failure`) for a SHA shared with a victim stack where blocking_statuses configured, so `StatusHandler#process` (no repository scoping) flips the required context and, because a forced status can set/clear `blocked?` and gate deploys, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/coverage`,`state: failure`; victim stack has blocking_statuses configured
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `blocking_statuses configured` (a forced status can set/clear `blocked?` and gate deploys) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `ci/coverage` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: victim stack with blocking_statuses configured requiring `ci/coverage`; process the `failure` status; assert deployability/merge/block changed.

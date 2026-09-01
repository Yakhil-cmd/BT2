# Q1762: [failure] status `review/approved` on a blocking_statuses configured stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: review/approved`, `state: failure`) for a SHA shared with a victim stack where blocking_statuses configured, so `StatusHandler#process` (no repository scoping) flips the required context and, because a forced status can set/clear `blocked?` and gate deploys, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: review/approved`,`state: failure`; victim stack has blocking_statuses configured
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `blocking_statuses configured` (a forced status can set/clear `blocked?` and gate deploys) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `review/approved` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: victim stack with blocking_statuses configured requiring `review/approved`; process the `failure` status; assert deployability/merge/block changed.

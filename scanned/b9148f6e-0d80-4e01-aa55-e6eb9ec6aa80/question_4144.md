# Q4144: [success] status `continuous-integration/travis-ci` on a blocking_statuses configured stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: continuous-integration/travis-ci`, `state: success`) for a SHA shared with a victim stack where blocking_statuses configured, so `StatusHandler#process` (no repository scoping) flips the required context and, because a forced status can set/clear `blocked?` and gate deploys, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: continuous-integration/travis-ci`,`state: success`; victim stack has blocking_statuses configured
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `blocking_statuses configured` (a forced status can set/clear `blocked?` and gate deploys) turns the flip into a `success`-driven ship/block
- Invariant to test: A `continuous-integration/travis-ci` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: victim stack with blocking_statuses configured requiring `continuous-integration/travis-ci`; process the `success` status; assert deployability/merge/block changed.

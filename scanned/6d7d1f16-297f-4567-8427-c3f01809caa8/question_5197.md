# Q5197: Unscoped status `continuous-integration/travis-ci` amplified by blocking_statuses configured

## Question
Can an unprivileged attacker send a `status` webhook for context `continuous-integration/travis-ci` on a SHA shared with a victim stack where blocking_statuses configured, so `StatusHandler#process` (no repo scoping) flips CI state and, because a forced status can set/clear `blocked?` and gate deploys, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: continuous-integration/travis-ci`,`state`; victim stack has blocking_statuses configured
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `blocking_statuses configured` (a forced status can set/clear `blocked?` and gate deploys) it forces a deploy/merge/block
- Invariant to test: A status for `continuous-integration/travis-ci` only affects the repository that authenticated it, irrespective of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: seed a victim stack with blocking_statuses configured requiring `continuous-integration/travis-ci`, share the SHA, process the status, assert the ship/block.

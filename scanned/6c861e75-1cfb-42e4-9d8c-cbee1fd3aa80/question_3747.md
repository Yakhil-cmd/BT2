# Q3747: Unscoped status `deploy/production` amplified by continuous_deployment enabled

## Question
Can an unprivileged attacker send a `status` webhook for context `deploy/production` on a SHA shared with a victim stack where continuous_deployment enabled, so `StatusHandler#process` (no repo scoping) flips CI state and, because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: deploy/production`,`state`; victim stack has continuous_deployment enabled
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `continuous_deployment enabled` (the victim stack auto-ships newly-green commits via ContinuousDeliveryJob) it forces a deploy/merge/block
- Invariant to test: A status for `deploy/production` only affects the repository that authenticated it, irrespective of continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed a victim stack with continuous_deployment enabled requiring `deploy/production`, share the SHA, process the status, assert the ship/block.

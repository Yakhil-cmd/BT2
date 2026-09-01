# Q3436: [success] status `ci/lint` on a continuous_deployment enabled stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: ci/lint`, `state: success`) for a SHA shared with a victim stack where continuous_deployment enabled, so `StatusHandler#process` (no repository scoping) flips the required context and, because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/lint`,`state: success`; victim stack has continuous_deployment enabled
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `continuous_deployment enabled` (the victim stack auto-ships newly-green commits via ContinuousDeliveryJob) turns the flip into a `success`-driven ship/block
- Invariant to test: A `ci/lint` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with continuous_deployment enabled requiring `ci/lint`; process the `success` status; assert deployability/merge/block changed.

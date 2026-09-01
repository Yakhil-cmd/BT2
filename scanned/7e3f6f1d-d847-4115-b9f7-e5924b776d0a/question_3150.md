# Q3150: [failure] status `codecov/project` on a merge_queue_enabled true stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: codecov/project`, `state: failure`) for a SHA shared with a victim stack where merge_queue_enabled true, so `StatusHandler#process` (no repository scoping) flips the required context and, because a green head advances the merge queue and `merge!` fires, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: codecov/project`,`state: failure`; victim stack has merge_queue_enabled true
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `merge_queue_enabled true` (a green head advances the merge queue and `merge!` fires) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `codecov/project` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with merge_queue_enabled true requiring `codecov/project`; process the `failure` status; assert deployability/merge/block changed.

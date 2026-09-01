# Q2857: [success] status `ci/build` on a merge_queue_enabled true stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: ci/build`, `state: success`) for a SHA shared with a victim stack where merge_queue_enabled true, so `StatusHandler#process` (no repository scoping) flips the required context and, because a green head advances the merge queue and `merge!` fires, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/build`,`state: success`; victim stack has merge_queue_enabled true
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `merge_queue_enabled true` (a green head advances the merge queue and `merge!` fires) turns the flip into a `success`-driven ship/block
- Invariant to test: A `ci/build` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with merge_queue_enabled true requiring `ci/build`; process the `success` status; assert deployability/merge/block changed.

# Q4338: [failure] status `github-actions` on a merge_queue_enabled true stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: github-actions`, `state: failure`) for a SHA shared with a victim stack where merge_queue_enabled true, so `StatusHandler#process` (no repository scoping) flips the required context and, because a green head advances the merge queue and `merge!` fires, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: github-actions`,`state: failure`; victim stack has merge_queue_enabled true
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `merge_queue_enabled true` (a green head advances the merge queue and `merge!` fires) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `github-actions` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with merge_queue_enabled true requiring `github-actions`; process the `failure` status; assert deployability/merge/block changed.

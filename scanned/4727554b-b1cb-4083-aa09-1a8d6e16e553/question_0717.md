# Q0717: Unscoped status `release/gate` amplified by merge_queue_enabled true

## Question
Can an unprivileged attacker send a `status` webhook for context `release/gate` on a SHA shared with a victim stack where merge_queue_enabled true, so `StatusHandler#process` (no repo scoping) flips CI state and, because a green head advances the merge queue and `merge!` fires, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: release/gate`,`state`; victim stack has merge_queue_enabled true
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `merge_queue_enabled true` (a green head advances the merge queue and `merge!` fires) it forces a deploy/merge/block
- Invariant to test: A status for `release/gate` only affects the repository that authenticated it, irrespective of merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed a victim stack with merge_queue_enabled true requiring `release/gate`, share the SHA, process the status, assert the ship/block.

# Q0197: [owner/full_name split] `status` -> StatusHandler on a merge_queue_enabled true stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `status` event against a victim stack where merge_queue_enabled true, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has merge_queue_enabled true
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; a green head advances the merge queue and `merge!` fires amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `owner/full_name split`, forge `status` for a merge_queue_enabled true stack, assert the downstream effect.

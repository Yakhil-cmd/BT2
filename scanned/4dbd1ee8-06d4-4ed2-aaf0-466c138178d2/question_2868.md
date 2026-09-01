# Q2868: [organization fallback selection] `pull_request` action=`edited` -> EditedHandler on a merge_queue_enabled true stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`edited` event against a victim stack where merge_queue_enabled true, can an unprivileged attacker make `EditedHandler` (updates the persisted `PullRequest` record from `params.pull_request`) cause impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`edited`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has merge_queue_enabled true
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`; a green head advances the merge queue and `merge!` fires amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`edited` for a merge_queue_enabled true stack, assert the downstream effect.

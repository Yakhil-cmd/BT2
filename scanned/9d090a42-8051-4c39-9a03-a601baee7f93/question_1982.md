# Q1982: [organization fallback selection] `pull_request` action=`reopened` -> ReopenedHandler on a merge_queue_enabled true stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`reopened` event against a victim stack where merge_queue_enabled true, can an unprivileged attacker make `ReopenedHandler` (unarchives / recreates a `ReviewStack` for the PR) cause impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has merge_queue_enabled true
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `ReopenedHandler` unarchives / recreates a `ReviewStack` for the PR; a green head advances the merge queue and `merge!` fires amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`reopened` for a merge_queue_enabled true stack, assert the downstream effect.

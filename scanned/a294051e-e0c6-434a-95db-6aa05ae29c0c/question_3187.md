# Q3187: [organization fallback selection] `pull_request` action=`unassigned` -> AssignedHandler on a org configured without webhook_secret stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`unassigned` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unassigned`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has org configured without webhook_secret
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`unassigned` for a org configured without webhook_secret stack, assert the downstream effect.

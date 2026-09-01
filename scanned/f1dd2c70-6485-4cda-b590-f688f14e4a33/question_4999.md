# Q4999: [organization fallback selection] `pull_request` action=`unassigned` -> AssignedHandler on a ignore_ci true stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`unassigned` event against a victim stack where ignore_ci true, can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unassigned`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has ignore_ci true
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; `Commit#deployable?` short-circuits CI so any commit is shippable amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`unassigned` for a ignore_ci true stack, assert the downstream effect.

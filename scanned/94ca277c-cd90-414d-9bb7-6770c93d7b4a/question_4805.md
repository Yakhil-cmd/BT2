# Q4805: [owner/full_name split] `pull_request` action=`reopened` -> ReopenedHandler on a blocking_statuses configured stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `pull_request` action=`reopened` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `ReopenedHandler` (unarchives / recreates a `ReviewStack` for the PR) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has blocking_statuses configured
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `ReopenedHandler` unarchives / recreates a `ReviewStack` for the PR; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `owner/full_name split`, forge `pull_request` action=`reopened` for a blocking_statuses configured stack, assert the downstream effect.

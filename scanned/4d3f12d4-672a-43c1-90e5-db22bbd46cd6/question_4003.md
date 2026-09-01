# Q4003: [owner/full_name split] `pull_request` action=`reopened` -> ReopenedHandler on a production environment stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `pull_request` action=`reopened` event against a victim stack where production environment, can an unprivileged attacker make `ReopenedHandler` (unarchives / recreates a `ReviewStack` for the PR) cause impact because the affected stack is the production environment?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has production environment
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `ReopenedHandler` unarchives / recreates a `ReviewStack` for the PR; the affected stack is the production environment amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of production environment.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `owner/full_name split`, forge `pull_request` action=`reopened` for a production environment stack, assert the downstream effect.

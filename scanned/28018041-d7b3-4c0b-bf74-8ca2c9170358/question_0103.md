# Q0103: [unknown-organization error path] `pull_request` action=`edited` -> EditedHandler on a org configured without webhook_secret stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`edited` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `EditedHandler` (updates the persisted `PullRequest` record from `params.pull_request`) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`edited`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has org configured without webhook_secret
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`edited` for a org configured without webhook_secret stack, assert the downstream effect.

# Q3506: [unknown-organization error path] `pull_request` action=`unassigned` -> AssignedHandler on a org configured without webhook_secret stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`unassigned` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unassigned`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has org configured without webhook_secret
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`unassigned` for a org configured without webhook_secret stack, assert the downstream effect.

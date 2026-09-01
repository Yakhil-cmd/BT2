# Q1519: [unknown-organization error path] `pull_request` action=`opened` -> OpenedHandler on a org configured without webhook_secret stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`opened` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `OpenedHandler` (provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has org configured without webhook_secret
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `OpenedHandler` provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`opened` for a org configured without webhook_secret stack, assert the downstream effect.

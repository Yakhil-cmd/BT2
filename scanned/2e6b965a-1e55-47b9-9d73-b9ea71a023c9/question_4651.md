# Q4651: [unknown-organization error path] `pull_request` action=`closed` -> ClosedHandler on a blocking_statuses configured stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`closed` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `ClosedHandler` (archives the `ReviewStack` bound to the PR number) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`closed`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has blocking_statuses configured
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `ClosedHandler` archives the `ReviewStack` bound to the PR number; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`closed` for a blocking_statuses configured stack, assert the downstream effect.

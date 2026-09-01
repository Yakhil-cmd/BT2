# Q1004: [unknown-organization error path] `pull_request` action=`closed` -> ClosedHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`closed` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `ClosedHandler` (archives the `ReviewStack` bound to the PR number) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`closed`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has bot_login configured (Shipit.user)
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `ClosedHandler` archives the `ReviewStack` bound to the PR number; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`closed` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

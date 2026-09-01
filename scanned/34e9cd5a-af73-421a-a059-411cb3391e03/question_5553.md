# Q5553: [unknown-organization error path] `pull_request` action=`closed` -> ClosedHandler on a review_stacks_enabled false stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`closed` event against a victim stack where review_stacks_enabled false, can an unprivileged attacker make `ClosedHandler` (archives the `ReviewStack` bound to the PR number) cause impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`closed`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has review_stacks_enabled false
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `ClosedHandler` archives the `ReviewStack` bound to the PR number; review stacks are supposedly disabled yet the provision? precedence bug still provisions amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`closed` for a review_stacks_enabled false stack, assert the downstream effect.

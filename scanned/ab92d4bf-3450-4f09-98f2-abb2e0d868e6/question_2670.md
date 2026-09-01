# Q2670: [unknown-organization error path] `pull_request` action=`edited` -> EditedHandler on a ignore_ci true stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`edited` event against a victim stack where ignore_ci true, can an unprivileged attacker make `EditedHandler` (updates the persisted `PullRequest` record from `params.pull_request`) cause impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`edited`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has ignore_ci true
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`; `Commit#deployable?` short-circuits CI so any commit is shippable amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`edited` for a ignore_ci true stack, assert the downstream effect.

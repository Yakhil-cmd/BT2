# Q4004: [unknown-organization error path] `pull_request` action=`unlabeled` -> UnlabeledHandler on a continuous_deployment enabled stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`unlabeled` event against a victim stack where continuous_deployment enabled, can an unprivileged attacker make `UnlabeledHandler` (archives or unarchives the review stack based on the provisioning label) cause impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unlabeled`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has continuous_deployment enabled
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `UnlabeledHandler` archives or unarchives the review stack based on the provisioning label; the victim stack auto-ships newly-green commits via ContinuousDeliveryJob amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`unlabeled` for a continuous_deployment enabled stack, assert the downstream effect.

# Q1765: [unknown-organization error path] `pull_request` action=`labeled` -> LabelCapturingHandler on a merge_queue_enabled true stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`labeled` event against a victim stack where merge_queue_enabled true, can an unprivileged attacker make `LabelCapturingHandler` (persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`) cause impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`labeled`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has merge_queue_enabled true
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `LabelCapturingHandler` persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`; a green head advances the merge queue and `merge!` fires amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`labeled` for a merge_queue_enabled true stack, assert the downstream effect.

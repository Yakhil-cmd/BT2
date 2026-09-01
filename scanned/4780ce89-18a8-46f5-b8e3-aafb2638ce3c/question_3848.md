# Q3848: [unknown-organization error path] `pull_request` action=`unassigned` -> AssignedHandler on a review_stacks_enabled true, allow_all stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` action=`unassigned` event against a victim stack where review_stacks_enabled true, allow_all, can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unassigned`, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; external PRs auto-provision review stacks that execute shipit.yml amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `unknown-organization error path`, forge `pull_request` action=`unassigned` for a review_stacks_enabled true, allow_all stack, assert the downstream effect.

# Q2666: [unknown-organization error path] `check_suite` -> CheckSuiteHandler on a shared commit SHA with attacker repo stack

## Question
Combining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `check_suite` event against a victim stack where shared commit SHA with attacker repo, can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on; victim stack has shared commit SHA with attacker repo
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; a status/commit lookup by bare SHA collides with the victim's commit amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `unknown-organization error path`, forge `check_suite` for a shared commit SHA with attacker repo stack, assert the downstream effect.

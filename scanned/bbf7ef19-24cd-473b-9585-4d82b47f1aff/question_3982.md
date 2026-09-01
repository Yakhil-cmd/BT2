# Q3982: unknown-organization error path -> archive a victim's active review stack

## Question
Chaining the `unknown-organization error path` verification gap (attacker targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on) with a `pull_request` handler, can an unprivileged attacker archive a victim's active review stack on a repository they do not own?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body plus signature/headers; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs, and the accepted `pull_request` event lets the attacker archive a victim's active review stack
- Invariant to test: A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge the `pull_request` event under the `unknown-organization error path` condition, assert the downstream mutation for the victim occurred.

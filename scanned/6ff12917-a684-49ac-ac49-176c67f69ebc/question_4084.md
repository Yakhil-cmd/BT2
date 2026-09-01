# Q4084: Forged pull_request `opened` via unknown-organization error path drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: opened` that targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: opened`, event header, and signature; targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; the `head(422)` on an unknown org actually halts the filter chain before `create` runs
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`opened` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

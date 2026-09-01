# Q5366: Forged pull_request `reopened` via organization fallback selection drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: reopened` that omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: reopened`, event header, and signature; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`reopened` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

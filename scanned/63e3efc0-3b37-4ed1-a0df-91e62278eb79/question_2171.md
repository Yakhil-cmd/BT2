# Q2171: Forged pull_request `labeled` via legacy sha1 signature header drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: labeled` that supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: labeled`, event header, and signature; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`labeled` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

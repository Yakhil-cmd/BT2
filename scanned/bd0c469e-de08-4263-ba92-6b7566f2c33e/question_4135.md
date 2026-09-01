# Q4135: Forged pull_request `synchronize` via nil / malformed signature split drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: synchronize` that sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: synchronize`, event header, and signature; sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; the comparison inputs are attacker-shaped and, for a no-secret org, never reached because verification short-circuits to true
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`synchronize` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

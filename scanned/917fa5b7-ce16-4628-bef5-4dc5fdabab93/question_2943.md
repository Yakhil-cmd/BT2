# Q2943: Forged pull_request `reopened` via no-secret organization drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: reopened` that sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: reopened`, event header, and signature; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`reopened` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

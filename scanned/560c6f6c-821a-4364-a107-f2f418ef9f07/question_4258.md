# Q4258: Forged pull_request `assigned` via owner/full_name split drives review-stack lifecycle

## Question
Can an unprivileged attacker POST a `pull_request` webhook with `action: assigned` that names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves, so the matching PullRequest handler acts on a victim repository's review stack without a valid webhook_secret?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body with `action: assigned`, event header, and signature; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves
- Exploit idea: `Webhooks.for_event('pull_request')` fans out to all PR handlers; the org selected to verify the signature is not the org that owns the repository the handler mutates
- Invariant to test: The organization whose webhook_secret verified the event owns the review stack / repository the PR handler mutates.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge a `pull_request`/`assigned` event for a no-secret org targeting a victim repo, assert the handler side effect landed.

# Q3145: no-secret organization -> archive a victim's active review stack

## Question
Chaining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `pull_request` handler, can an unprivileged attacker archive a victim's active review stack on a repository they do not own?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body plus signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC, and the accepted `pull_request` event lets the attacker archive a victim's active review stack
- Invariant to test: A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: forge the `pull_request` event under the `no-secret organization` condition, assert the downstream mutation for the victim occurred.

# Q3951: no-secret organization -> mark a victim commit deployable and ship it

## Question
Chaining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `status` handler, can an unprivileged attacker mark a victim commit deployable and ship it on a repository they do not own?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body plus signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC, and the accepted `status` event lets the attacker mark a victim commit deployable and ship it
- Invariant to test: A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: forge the `status` event under the `no-secret organization` condition, assert the downstream mutation for the victim occurred.

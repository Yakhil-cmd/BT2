# Q4223: [no-secret organization] `pull_request` action=`closed` -> ClosedHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `pull_request` action=`closed` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `ClosedHandler` (archives the `ReviewStack` bound to the PR number) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`closed`, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has bot_login configured (Shipit.user)
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `ClosedHandler` archives the `ReviewStack` bound to the PR number; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `no-secret organization`, forge `pull_request` action=`closed` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

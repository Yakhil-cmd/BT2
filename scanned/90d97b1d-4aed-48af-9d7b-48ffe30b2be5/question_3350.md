# Q3350: [no-secret organization] `pull_request` action=`closed` -> ClosedHandler on a blocking_statuses configured stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `pull_request` action=`closed` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `ClosedHandler` (archives the `ReviewStack` bound to the PR number) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`closed`, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `ClosedHandler` archives the `ReviewStack` bound to the PR number; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `no-secret organization`, forge `pull_request` action=`closed` for a blocking_statuses configured stack, assert the downstream effect.

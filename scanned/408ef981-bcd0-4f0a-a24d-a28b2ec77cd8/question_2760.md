# Q2760: [no-secret organization] `membership` action=`added` -> MembershipHandler on a blocking_statuses configured stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `membership` action=`added` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `MembershipHandler` (creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`added`, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `membership` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `no-secret organization`, forge `membership` action=`added` for a blocking_statuses configured stack, assert the downstream effect.

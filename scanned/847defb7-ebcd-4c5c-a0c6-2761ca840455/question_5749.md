# Q5749: [no-secret organization] `membership` action=`removed` -> MembershipHandler on a shared commit SHA with attacker repo stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `membership` action=`removed` event against a victim stack where shared commit SHA with attacker repo, can an unprivileged attacker make `MembershipHandler` (creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads) cause impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has shared commit SHA with attacker repo
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads; a status/commit lookup by bare SHA collides with the victim's commit amplifies the effect
- Invariant to test: A `membership` event only affects the repository/stack whose secret authenticated it, regardless of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `no-secret organization`, forge `membership` action=`removed` for a shared commit SHA with attacker repo stack, assert the downstream effect.

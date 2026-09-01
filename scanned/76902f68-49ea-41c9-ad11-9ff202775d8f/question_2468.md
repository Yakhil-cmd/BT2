# Q2468: Forged `membership` action=`removed` vs a stack where blocking_statuses configured (MembershipHandler)

## Question
Against a victim stack where blocking_statuses configured (a forced status can set/clear `blocked?` and gate deploys), can an unprivileged attacker forge a `membership` action=`removed` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, event header, signature; targets an org with no webhook_secret and a stack where blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because a forced status can set/clear `blocked?` and gate deploys the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with blocking_statuses configured, forge the `membership` event, assert the amplified downstream effect occurred.

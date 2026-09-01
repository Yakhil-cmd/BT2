# Q0472: Forged `membership` action=`removed` vs a stack where shared commit SHA with attacker repo (MembershipHandler)

## Question
Against a victim stack where shared commit SHA with attacker repo (a status/commit lookup by bare SHA collides with the victim's commit), can an unprivileged attacker forge a `membership` action=`removed` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, event header, signature; targets an org with no webhook_secret and a stack where shared commit SHA with attacker repo
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because a status/commit lookup by bare SHA collides with the victim's commit the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with shared commit SHA with attacker repo, forge the `membership` event, assert the amplified downstream effect occurred.

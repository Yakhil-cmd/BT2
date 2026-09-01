# Q3653: Forged `membership` action=`removed` vs a stack where bot_login configured (Shipit.user) (MembershipHandler)

## Question
Against a victim stack where bot_login configured (Shipit.user) (auto-triggered deploys run as the configured bot identity), can an unprivileged attacker forge a `membership` action=`removed` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, event header, signature; targets an org with no webhook_secret and a stack where bot_login configured (Shipit.user)
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because auto-triggered deploys run as the configured bot identity the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with bot_login configured (Shipit.user), forge the `membership` event, assert the amplified downstream effect occurred.

# Q2001: Forged `membership` action=`removed` vs a stack where review_stacks_enabled false (MembershipHandler)

## Question
Against a victim stack where review_stacks_enabled false (review stacks are supposedly disabled yet the provision? precedence bug still provisions), can an unprivileged attacker forge a `membership` action=`removed` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled false
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because review stacks are supposedly disabled yet the provision? precedence bug still provisions the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled false, forge the `membership` event, assert the amplified downstream effect occurred.

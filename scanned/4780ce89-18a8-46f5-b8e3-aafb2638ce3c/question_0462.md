# Q0462: Forged `membership` action=`added` vs a stack where merge_queue_enabled true (MembershipHandler)

## Question
Against a victim stack where merge_queue_enabled true (a green head advances the merge queue and `merge!` fires), can an unprivileged attacker forge a `membership` action=`added` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`added`, event header, signature; targets an org with no webhook_secret and a stack where merge_queue_enabled true
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because a green head advances the merge queue and `merge!` fires the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with merge_queue_enabled true, forge the `membership` event, assert the amplified downstream effect occurred.

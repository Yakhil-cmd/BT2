# Q5147: Forged `membership` action=`removed` vs a stack where review_stacks_enabled true, allow_all (MembershipHandler)

## Question
Against a victim stack where review_stacks_enabled true, allow_all (external PRs auto-provision review stacks that execute shipit.yml), can an unprivileged attacker forge a `membership` action=`removed` webhook for an org with no configured webhook_secret so `MembershipHandler`, which creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, produces impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/membership_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body action=`removed`, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `MembershipHandler` creates/finds a `Team` by `params.team.id` and a `User` by `params.member.login` then adds or removes the membership rows that `User#authorized?` reads, and because external PRs auto-provision review stacks that execute shipit.yml the effect is amplified
- Invariant to test: A forged `membership` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled true, allow_all, forge the `membership` event, assert the amplified downstream effect occurred.

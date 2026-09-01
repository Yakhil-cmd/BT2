# Q4654: Forged `pull_request` action=`opened` vs a stack where blocking_statuses configured (OpenedHandler)

## Question
Against a victim stack where blocking_statuses configured (a forced status can set/clear `blocked?` and gate deploys), can an unprivileged attacker forge a `pull_request` action=`opened` webhook for an org with no configured webhook_secret so `OpenedHandler`, which provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, produces impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, event header, signature; targets an org with no webhook_secret and a stack where blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `OpenedHandler` provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, and because a forced status can set/clear `blocked?` and gate deploys the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with blocking_statuses configured, forge the `pull_request` event, assert the amplified downstream effect occurred.

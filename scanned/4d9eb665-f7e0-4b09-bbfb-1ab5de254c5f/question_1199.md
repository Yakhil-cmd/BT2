# Q1199: Forged `pull_request` action=`opened` vs a stack where continuous_deployment enabled (OpenedHandler)

## Question
Against a victim stack where continuous_deployment enabled (the victim stack auto-ships newly-green commits via ContinuousDeliveryJob), can an unprivileged attacker forge a `pull_request` action=`opened` webhook for an org with no configured webhook_secret so `OpenedHandler`, which provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, produces impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, event header, signature; targets an org with no webhook_secret and a stack where continuous_deployment enabled
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `OpenedHandler` provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, and because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with continuous_deployment enabled, forge the `pull_request` event, assert the amplified downstream effect occurred.

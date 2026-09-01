# Q4816: Forged `pull_request` action=`opened` vs a stack where merge_queue_enabled true (OpenedHandler)

## Question
Against a victim stack where merge_queue_enabled true (a green head advances the merge queue and `merge!` fires), can an unprivileged attacker forge a `pull_request` action=`opened` webhook for an org with no configured webhook_secret so `OpenedHandler`, which provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, produces impact because a green head advances the merge queue and `merge!` fires?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, event header, signature; targets an org with no webhook_secret and a stack where merge_queue_enabled true
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `OpenedHandler` provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, and because a green head advances the merge queue and `merge!` fires the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's merge_queue_enabled true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with merge_queue_enabled true, forge the `pull_request` event, assert the amplified downstream effect occurred.

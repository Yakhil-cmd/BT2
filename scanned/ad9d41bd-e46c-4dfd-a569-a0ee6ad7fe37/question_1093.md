# Q1093: Forged `pull_request` action=`assigned` vs a stack where blocking_statuses configured (AssignedHandler)

## Question
Against a victim stack where blocking_statuses configured (a forced status can set/clear `blocked?` and gate deploys), can an unprivileged attacker forge a `pull_request` action=`assigned` webhook for an org with no configured webhook_secret so `AssignedHandler`, which updates the persisted `PullRequest` record on assignee change, produces impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`assigned`, event header, signature; targets an org with no webhook_secret and a stack where blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `AssignedHandler` updates the persisted `PullRequest` record on assignee change, and because a forced status can set/clear `blocked?` and gate deploys the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with blocking_statuses configured, forge the `pull_request` event, assert the amplified downstream effect occurred.

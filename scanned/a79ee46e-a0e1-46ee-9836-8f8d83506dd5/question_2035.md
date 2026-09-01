# Q2035: Forged `push` vs a stack where blocking_statuses configured (PushHandler)

## Question
Against a victim stack where blocking_statuses configured (a forced status can set/clear `blocked?` and gate deploys), can an unprivileged attacker forge a `push` webhook for an org with no configured webhook_secret so `PushHandler`, which syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, produces impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, event header, signature; targets an org with no webhook_secret and a stack where blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, and because a forced status can set/clear `blocked?` and gate deploys the effect is amplified
- Invariant to test: A forged `push` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with blocking_statuses configured, forge the `push` event, assert the amplified downstream effect occurred.

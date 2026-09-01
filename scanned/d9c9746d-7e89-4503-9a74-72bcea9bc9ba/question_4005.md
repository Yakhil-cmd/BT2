# Q4005: Forged `push` vs a stack where org configured without webhook_secret (PushHandler)

## Question
Against a victim stack where org configured without webhook_secret (forged webhooks for this org are accepted unconditionally), can an unprivileged attacker forge a `push` webhook for an org with no configured webhook_secret so `PushHandler`, which syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, produces impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, event header, signature; targets an org with no webhook_secret and a stack where org configured without webhook_secret
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, and because forged webhooks for this org are accepted unconditionally the effect is amplified
- Invariant to test: A forged `push` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: configure a stack with org configured without webhook_secret, forge the `push` event, assert the amplified downstream effect occurred.

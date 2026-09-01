# Q2314: Forged `push` vs a stack where review_stacks_enabled false (PushHandler)

## Question
Against a victim stack where review_stacks_enabled false (review stacks are supposedly disabled yet the provision? precedence bug still provisions), can an unprivileged attacker forge a `push` webhook for an org with no configured webhook_secret so `PushHandler`, which syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, produces impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled false
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, and because review stacks are supposedly disabled yet the provision? precedence bug still provisions the effect is amplified
- Invariant to test: A forged `push` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled false, forge the `push` event, assert the amplified downstream effect occurred.

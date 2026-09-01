# Q5137: Forged `push` vs a stack where review_stacks_enabled true, allow_all (PushHandler)

## Question
Against a victim stack where review_stacks_enabled true, allow_all (external PRs auto-provision review stacks that execute shipit.yml), can an unprivileged attacker forge a `push` webhook for an org with no configured webhook_secret so `PushHandler`, which syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, produces impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, and because external PRs auto-provision review stacks that execute shipit.yml the effect is amplified
- Invariant to test: A forged `push` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled true, allow_all, forge the `push` event, assert the amplified downstream effect occurred.

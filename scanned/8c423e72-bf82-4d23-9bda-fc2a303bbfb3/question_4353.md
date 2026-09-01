# Q4353: Forged `status` vs a stack where continuous_deployment enabled (StatusHandler)

## Question
Against a victim stack where continuous_deployment enabled (the victim stack auto-ships newly-green commits via ContinuousDeliveryJob), can an unprivileged attacker forge a `status` webhook for an org with no configured webhook_secret so `StatusHandler`, which runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all, produces impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, event header, signature; targets an org with no webhook_secret and a stack where continuous_deployment enabled
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all, and because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob the effect is amplified
- Invariant to test: A forged `status` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with continuous_deployment enabled, forge the `status` event, assert the amplified downstream effect occurred.

# Q2399: Forged `pull_request` action=`reopened` vs a stack where production environment (ReopenedHandler)

## Question
Against a victim stack where production environment (the affected stack is the production environment), can an unprivileged attacker forge a `pull_request` action=`reopened` webhook for an org with no configured webhook_secret so `ReopenedHandler`, which unarchives / recreates a `ReviewStack` for the PR, produces impact because the affected stack is the production environment?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, event header, signature; targets an org with no webhook_secret and a stack where production environment
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `ReopenedHandler` unarchives / recreates a `ReviewStack` for the PR, and because the affected stack is the production environment the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's production environment.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with production environment, forge the `pull_request` event, assert the amplified downstream effect occurred.

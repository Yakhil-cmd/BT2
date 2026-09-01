# Q4082: Forged `pull_request` action=`labeled` vs a stack where production environment (LabeledHandler)

## Question
Against a victim stack where production environment (the affected stack is the production environment), can an unprivileged attacker forge a `pull_request` action=`labeled` webhook for an org with no configured webhook_secret so `LabeledHandler`, which archives or unarchives the review stack based on the provisioning label, produces impact because the affected stack is the production environment?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`labeled`, event header, signature; targets an org with no webhook_secret and a stack where production environment
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `LabeledHandler` archives or unarchives the review stack based on the provisioning label, and because the affected stack is the production environment the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's production environment.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with production environment, forge the `pull_request` event, assert the amplified downstream effect occurred.

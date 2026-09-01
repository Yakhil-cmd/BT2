# Q4646: Forged `pull_request` action=`unlabeled` vs a stack where shared commit SHA with attacker repo (UnlabeledHandler)

## Question
Against a victim stack where shared commit SHA with attacker repo (a status/commit lookup by bare SHA collides with the victim's commit), can an unprivileged attacker forge a `pull_request` action=`unlabeled` webhook for an org with no configured webhook_secret so `UnlabeledHandler`, which archives or unarchives the review stack based on the provisioning label, produces impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unlabeled`, event header, signature; targets an org with no webhook_secret and a stack where shared commit SHA with attacker repo
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `UnlabeledHandler` archives or unarchives the review stack based on the provisioning label, and because a status/commit lookup by bare SHA collides with the victim's commit the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: configure a stack with shared commit SHA with attacker repo, forge the `pull_request` event, assert the amplified downstream effect occurred.

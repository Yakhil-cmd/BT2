# Q5298: Forged `pull_request` action=`edited` vs a stack where review_stacks_enabled true, allow_all (EditedHandler)

## Question
Against a victim stack where review_stacks_enabled true, allow_all (external PRs auto-provision review stacks that execute shipit.yml), can an unprivileged attacker forge a `pull_request` action=`edited` webhook for an org with no configured webhook_secret so `EditedHandler`, which updates the persisted `PullRequest` record from `params.pull_request`, produces impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`edited`, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`, and because external PRs auto-provision review stacks that execute shipit.yml the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled true, allow_all, forge the `pull_request` event, assert the amplified downstream effect occurred.

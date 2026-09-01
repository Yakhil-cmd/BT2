# Q5839: Forged `pull_request` action=`opened` vs a stack where review_stacks_enabled false (OpenedHandler)

## Question
Against a victim stack where review_stacks_enabled false (review stacks are supposedly disabled yet the provision? precedence bug still provisions), can an unprivileged attacker forge a `pull_request` action=`opened` webhook for an org with no configured webhook_secret so `OpenedHandler`, which provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, produces impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`opened`, event header, signature; targets an org with no webhook_secret and a stack where review_stacks_enabled false
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `OpenedHandler` provisions a `ReviewStack` from `params.pull_request.head.ref` via `ReviewStackAdapter#find_or_create!`, and because review stacks are supposedly disabled yet the provision? precedence bug still provisions the effect is amplified
- Invariant to test: A forged `pull_request` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: configure a stack with review_stacks_enabled false, forge the `pull_request` event, assert the amplified downstream effect occurred.

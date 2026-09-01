# Q3374: Unscoped status `security/scan` amplified by review_stacks_enabled false

## Question
Can an unprivileged attacker send a `status` webhook for context `security/scan` on a SHA shared with a victim stack where review_stacks_enabled false, so `StatusHandler#process` (no repo scoping) flips CI state and, because review stacks are supposedly disabled yet the provision? precedence bug still provisions, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: security/scan`,`state`; victim stack has review_stacks_enabled false
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `review_stacks_enabled false` (review stacks are supposedly disabled yet the provision? precedence bug still provisions) it forces a deploy/merge/block
- Invariant to test: A status for `security/scan` only affects the repository that authenticated it, irrespective of review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: seed a victim stack with review_stacks_enabled false requiring `security/scan`, share the SHA, process the status, assert the ship/block.

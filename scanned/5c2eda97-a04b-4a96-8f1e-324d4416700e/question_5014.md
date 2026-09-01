# Q5014: [success] status `review/approved` on a review_stacks_enabled false stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: review/approved`, `state: success`) for a SHA shared with a victim stack where review_stacks_enabled false, so `StatusHandler#process` (no repository scoping) flips the required context and, because review stacks are supposedly disabled yet the provision? precedence bug still provisions, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: review/approved`,`state: success`; victim stack has review_stacks_enabled false
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `review_stacks_enabled false` (review stacks are supposedly disabled yet the provision? precedence bug still provisions) turns the flip into a `success`-driven ship/block
- Invariant to test: A `review/approved` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: victim stack with review_stacks_enabled false requiring `review/approved`; process the `success` status; assert deployability/merge/block changed.

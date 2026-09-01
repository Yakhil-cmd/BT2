# Q4615: [failure] status `sonarqube` on a review_stacks_enabled false stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: sonarqube`, `state: failure`) for a SHA shared with a victim stack where review_stacks_enabled false, so `StatusHandler#process` (no repository scoping) flips the required context and, because review stacks are supposedly disabled yet the provision? precedence bug still provisions, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: sonarqube`,`state: failure`; victim stack has review_stacks_enabled false
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `review_stacks_enabled false` (review stacks are supposedly disabled yet the provision? precedence bug still provisions) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `sonarqube` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: victim stack with review_stacks_enabled false requiring `sonarqube`; process the `failure` status; assert deployability/merge/block changed.

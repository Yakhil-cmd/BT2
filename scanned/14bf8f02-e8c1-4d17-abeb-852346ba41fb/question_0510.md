# Q0510: [failure] status `ci/test` on a review_stacks_enabled true, allow_all stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: ci/test`, `state: failure`) for a SHA shared with a victim stack where review_stacks_enabled true, allow_all, so `StatusHandler#process` (no repository scoping) flips the required context and, because external PRs auto-provision review stacks that execute shipit.yml, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/test`,`state: failure`; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `review_stacks_enabled true, allow_all` (external PRs auto-provision review stacks that execute shipit.yml) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `ci/test` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: victim stack with review_stacks_enabled true, allow_all requiring `ci/test`; process the `failure` status; assert deployability/merge/block changed.

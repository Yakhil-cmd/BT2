# Q2158: [success] status `buildkite/deploy` on a review_stacks_enabled true, allow_all stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: buildkite/deploy`, `state: success`) for a SHA shared with a victim stack where review_stacks_enabled true, allow_all, so `StatusHandler#process` (no repository scoping) flips the required context and, because external PRs auto-provision review stacks that execute shipit.yml, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: buildkite/deploy`,`state: success`; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `review_stacks_enabled true, allow_all` (external PRs auto-provision review stacks that execute shipit.yml) turns the flip into a `success`-driven ship/block
- Invariant to test: A `buildkite/deploy` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: victim stack with review_stacks_enabled true, allow_all requiring `buildkite/deploy`; process the `success` status; assert deployability/merge/block changed.

# Q5424: Unscoped status `deploy/production` amplified by review_stacks_enabled true, allow_all

## Question
Can an unprivileged attacker send a `status` webhook for context `deploy/production` on a SHA shared with a victim stack where review_stacks_enabled true, allow_all, so `StatusHandler#process` (no repo scoping) flips CI state and, because external PRs auto-provision review stacks that execute shipit.yml, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: deploy/production`,`state`; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `review_stacks_enabled true, allow_all` (external PRs auto-provision review stacks that execute shipit.yml) it forces a deploy/merge/block
- Invariant to test: A status for `deploy/production` only affects the repository that authenticated it, irrespective of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: seed a victim stack with review_stacks_enabled true, allow_all requiring `deploy/production`, share the SHA, process the status, assert the ship/block.

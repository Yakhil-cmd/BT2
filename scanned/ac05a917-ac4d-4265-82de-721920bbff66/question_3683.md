# Q3683: Unscoped status `ci/build` amplified by ignore_ci true

## Question
Can an unprivileged attacker send a `status` webhook for context `ci/build` on a SHA shared with a victim stack where ignore_ci true, so `StatusHandler#process` (no repo scoping) flips CI state and, because `Commit#deployable?` short-circuits CI so any commit is shippable, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/build`,`state`; victim stack has ignore_ci true
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `ignore_ci true` (`Commit#deployable?` short-circuits CI so any commit is shippable) it forces a deploy/merge/block
- Invariant to test: A status for `ci/build` only affects the repository that authenticated it, irrespective of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed a victim stack with ignore_ci true requiring `ci/build`, share the SHA, process the status, assert the ship/block.

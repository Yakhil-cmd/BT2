# Q0195: Unscoped status `ci/circleci` amplified by bot_login configured (Shipit.user)

## Question
Can an unprivileged attacker send a `status` webhook for context `ci/circleci` on a SHA shared with a victim stack where bot_login configured (Shipit.user), so `StatusHandler#process` (no repo scoping) flips CI state and, because auto-triggered deploys run as the configured bot identity, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/circleci`,`state`; victim stack has bot_login configured (Shipit.user)
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `bot_login configured (Shipit.user)` (auto-triggered deploys run as the configured bot identity) it forces a deploy/merge/block
- Invariant to test: A status for `ci/circleci` only affects the repository that authenticated it, irrespective of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: seed a victim stack with bot_login configured (Shipit.user) requiring `ci/circleci`, share the SHA, process the status, assert the ship/block.

# Q3405: [success] status `shipit/checks` on a bot_login configured (Shipit.user) stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: shipit/checks`, `state: success`) for a SHA shared with a victim stack where bot_login configured (Shipit.user), so `StatusHandler#process` (no repository scoping) flips the required context and, because auto-triggered deploys run as the configured bot identity, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: shipit/checks`,`state: success`; victim stack has bot_login configured (Shipit.user)
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `bot_login configured (Shipit.user)` (auto-triggered deploys run as the configured bot identity) turns the flip into a `success`-driven ship/block
- Invariant to test: A `shipit/checks` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with bot_login configured (Shipit.user) requiring `shipit/checks`; process the `success` status; assert deployability/merge/block changed.

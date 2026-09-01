# Q3030: [success] status `continuous-integration/travis-ci` on a production environment stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: continuous-integration/travis-ci`, `state: success`) for a SHA shared with a victim stack where production environment, so `StatusHandler#process` (no repository scoping) flips the required context and, because the affected stack is the production environment, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: continuous-integration/travis-ci`,`state: success`; victim stack has production environment
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `production environment` (the affected stack is the production environment) turns the flip into a `success`-driven ship/block
- Invariant to test: A `continuous-integration/travis-ci` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: victim stack with production environment requiring `continuous-integration/travis-ci`; process the `success` status; assert deployability/merge/block changed.

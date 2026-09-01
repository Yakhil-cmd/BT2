# Q0858: Unscoped status `continuous-integration/travis-ci` amplified by shared commit SHA with attacker repo

## Question
Can an unprivileged attacker send a `status` webhook for context `continuous-integration/travis-ci` on a SHA shared with a victim stack where shared commit SHA with attacker repo, so `StatusHandler#process` (no repo scoping) flips CI state and, because a status/commit lookup by bare SHA collides with the victim's commit, causes a ship or block on that stack?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb + app/models/shipit/stack.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: continuous-integration/travis-ci`,`state`; victim stack has shared commit SHA with attacker repo
- Exploit idea: `StatusHandler` writes to the commit by bare SHA across repos; combined with `shared commit SHA with attacker repo` (a status/commit lookup by bare SHA collides with the victim's commit) it forces a deploy/merge/block
- Invariant to test: A status for `continuous-integration/travis-ci` only affects the repository that authenticated it, irrespective of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: seed a victim stack with shared commit SHA with attacker repo requiring `continuous-integration/travis-ci`, share the SHA, process the status, assert the ship/block.

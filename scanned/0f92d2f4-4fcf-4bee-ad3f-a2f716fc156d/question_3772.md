# Q3772: [failure] status `ci/kubernetes` on a shared commit SHA with attacker repo stack (unscoped)

## Question
Can an unprivileged attacker send a `status` webhook (`context: ci/kubernetes`, `state: failure`) for a SHA shared with a victim stack where shared commit SHA with attacker repo, so `StatusHandler#process` (no repository scoping) flips the required context and, because a status/commit lookup by bare SHA collides with the victim's commit, forces a ship or block?

## Target
- File/function: app/models/shipit/webhooks/handlers/status_handler.rb + app/models/shipit/commit.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: status `sha`,`context: ci/kubernetes`,`state: failure`; victim stack has shared commit SHA with attacker repo
- Exploit idea: `StatusHandler` writes by bare SHA across repos; `shared commit SHA with attacker repo` (a status/commit lookup by bare SHA collides with the victim's commit) turns the flip into a `failure`-driven ship/block
- Invariant to test: A `ci/kubernetes` status affects only the repository that authenticated it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: victim stack with shared commit SHA with attacker repo requiring `ci/kubernetes`; process the `failure` status; assert deployability/merge/block changed.

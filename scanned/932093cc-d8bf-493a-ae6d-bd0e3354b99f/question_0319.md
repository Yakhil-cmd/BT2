# Q0319: [nil / malformed signature split] `status` -> StatusHandler on a shared commit SHA with attacker repo stack

## Question
Combining the `nil / malformed signature split` verification gap (attacker sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`) with a `status` event against a victim stack where shared commit SHA with attacker repo, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`; victim stack has shared commit SHA with attacker repo
- Exploit idea: the comparison inputs are attacker-shaped and, for a no-secret org, never reached because verification short-circuits to true; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; a status/commit lookup by bare SHA collides with the victim's commit amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `nil / malformed signature split`, forge `status` for a shared commit SHA with attacker repo stack, assert the downstream effect.

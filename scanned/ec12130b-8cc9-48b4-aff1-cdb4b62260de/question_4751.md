# Q4751: [organization fallback selection] `pull_request` action=`reopened` -> ReopenedHandler on a shared commit SHA with attacker repo stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `pull_request` action=`reopened` event against a victim stack where shared commit SHA with attacker repo, can an unprivileged attacker make `ReopenedHandler` (unarchives / recreates a `ReviewStack` for the PR) cause impact because a status/commit lookup by bare SHA collides with the victim's commit?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`reopened`, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has shared commit SHA with attacker repo
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `ReopenedHandler` unarchives / recreates a `ReviewStack` for the PR; a status/commit lookup by bare SHA collides with the victim's commit amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of shared commit SHA with attacker repo.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `organization fallback selection`, forge `pull_request` action=`reopened` for a shared commit SHA with attacker repo stack, assert the downstream effect.

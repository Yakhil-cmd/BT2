# Q1612: [no-secret organization] `status` -> StatusHandler on a review_stacks_enabled true, allow_all stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `status` event against a victim stack where review_stacks_enabled true, allow_all, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because external PRs auto-provision review stacks that execute shipit.yml?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has review_stacks_enabled true, allow_all
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; external PRs auto-provision review stacks that execute shipit.yml amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled true, allow_all.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `no-secret organization`, forge `status` for a review_stacks_enabled true, allow_all stack, assert the downstream effect.

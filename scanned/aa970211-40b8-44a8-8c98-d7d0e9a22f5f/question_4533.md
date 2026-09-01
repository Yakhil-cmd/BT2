# Q4533: [no-secret organization] `check_suite` -> CheckSuiteHandler on a blocking_statuses configured stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `check_suite` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has blocking_statuses configured
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `no-secret organization`, forge `check_suite` for a blocking_statuses configured stack, assert the downstream effect.

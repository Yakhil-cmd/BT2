# Q0244: [organization fallback selection] `check_suite` -> CheckSuiteHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `check_suite` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has bot_login configured (Shipit.user)
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `organization fallback selection`, forge `check_suite` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

# Q0869: [organization fallback selection] `check_suite` -> CheckSuiteHandler on a org configured without webhook_secret stack

## Question
Combining the `organization fallback selection` verification gap (attacker omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field) with a `check_suite` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field; victim stack has org configured without webhook_secret
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `organization fallback selection`, forge `check_suite` for a org configured without webhook_secret stack, assert the downstream effect.

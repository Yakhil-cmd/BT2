# Q2291: [owner/full_name split] `check_suite` -> CheckSuiteHandler on a org configured without webhook_secret stack

## Question
Combining the `owner/full_name split` verification gap (attacker names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves) with a `check_suite` event against a victim stack where org configured without webhook_secret, can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; names a no-secret org in `repository.owner.login` (chosen by `repository_owner`) while pointing `repository.full_name` at a DIFFERENT org's repository the handler resolves; victim stack has org configured without webhook_secret
- Exploit idea: the org selected to verify the signature is not the org that owns the repository the handler mutates; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; forged webhooks for this org are accepted unconditionally amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: under `owner/full_name split`, forge `check_suite` for a org configured without webhook_secret stack, assert the downstream effect.

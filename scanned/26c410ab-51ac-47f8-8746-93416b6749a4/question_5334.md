# Q5334: [legacy sha1 signature header] `check_suite` -> CheckSuiteHandler on a ignore_ci true stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `check_suite` event against a victim stack where ignore_ci true, can an unprivileged attacker make `CheckSuiteHandler` (selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`) cause impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has ignore_ci true
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`; `Commit#deployable?` short-circuits CI so any commit is shippable amplifies the effect
- Invariant to test: A `check_suite` event only affects the repository/stack whose secret authenticated it, regardless of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `legacy sha1 signature header`, forge `check_suite` for a ignore_ci true stack, assert the downstream effect.

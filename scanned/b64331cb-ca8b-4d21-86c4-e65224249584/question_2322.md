# Q2322: Forged `check_suite` vs a stack where org configured without webhook_secret (CheckSuiteHandler)

## Question
Against a victim stack where org configured without webhook_secret (forged webhooks for this org are accepted unconditionally), can an unprivileged attacker forge a `check_suite` webhook for an org with no configured webhook_secret so `CheckSuiteHandler`, which selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`, produces impact because forged webhooks for this org are accepted unconditionally?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, event header, signature; targets an org with no webhook_secret and a stack where org configured without webhook_secret
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`, and because forged webhooks for this org are accepted unconditionally the effect is amplified
- Invariant to test: A forged `check_suite` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's org configured without webhook_secret.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: configure a stack with org configured without webhook_secret, forge the `check_suite` event, assert the amplified downstream effect occurred.

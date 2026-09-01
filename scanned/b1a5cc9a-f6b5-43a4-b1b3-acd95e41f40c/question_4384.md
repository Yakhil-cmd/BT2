# Q4384: Forged `check_suite` vs a stack where continuous_deployment enabled (CheckSuiteHandler)

## Question
Against a victim stack where continuous_deployment enabled (the victim stack auto-ships newly-green commits via ContinuousDeliveryJob), can an unprivileged attacker forge a `check_suite` webhook for an org with no configured webhook_secret so `CheckSuiteHandler`, which selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`, produces impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `check_suite` body, event header, signature; targets an org with no webhook_secret and a stack where continuous_deployment enabled
- Exploit idea: `GitHubApp#verify_webhook_signature` returns true for the no-secret org, `CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`, and because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob the effect is amplified
- Invariant to test: A forged `check_suite` event cannot produce a state change on a stack it did not authenticate, regardless of that stack's continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: configure a stack with continuous_deployment enabled, forge the `check_suite` event, assert the amplified downstream effect occurred.

# Q2626: Forged `check_suite` webhook via organization fallback selection reaches CheckSuiteHandler

## Question
Can an unprivileged internet user POST a `check_suite` event to `/webhooks` that omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::CheckSuiteHandler` selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/check_suite_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: check_suite` header, and `X-Hub-Signature`; specifically it omits `repository` so `repository_owner` falls back to `organization.login`, choosing a lenient verifier while the handler reads the repo from another field
- Exploit idea: `repository_owner` (verifier selector) and the handler's `repository.full_name` come from different, independently attacker-set fields; the accepted body then drives `Shipit::Webhooks::Handlers::CheckSuiteHandler` which selects stacks by `params.check_suite.head_branch` and reschedules check-run refresh for commits matching `params.check_suite.head_sha`
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `check_suite` body, assert the handler ran and mutated a record owned by a different org.

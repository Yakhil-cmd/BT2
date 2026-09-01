# Q0818: PR field `pull_request.user.login` unsanitized persistence

## Question
In the pull_request handlers, can an unprivileged PR author set `pull_request.user.login` (which is trusted as the PR author identity) such that it is written to the database without validation/sanitization, breaking the assumption that a hostile value is stored and later rendered or used to build a command/URL?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.user.login` in the webhook body (is trusted as the PR author identity)
- Exploit idea: the field is written to the database without validation/sanitization; a hostile value is stored and later rendered or used to build a command/URL
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `pull_request.user.login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `pull_request.user.login`, assert which record was located/written and that it matches the intended repo+PR only.

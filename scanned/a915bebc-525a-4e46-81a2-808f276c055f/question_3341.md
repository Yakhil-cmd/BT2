# Q3341: PR field `pull_request.assignees[].login` unsanitized persistence

## Question
In the pull_request handlers, can an unprivileged PR author set `pull_request.assignees[].login` (which is stored as assignee identity) such that it is written to the database without validation/sanitization, breaking the assumption that a hostile value is stored and later rendered or used to build a command/URL?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.assignees[].login` in the webhook body (is stored as assignee identity)
- Exploit idea: the field is written to the database without validation/sanitization; a hostile value is stored and later rendered or used to build a command/URL
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `pull_request.assignees[].login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `pull_request.assignees[].login`, assert which record was located/written and that it matches the intended repo+PR only.

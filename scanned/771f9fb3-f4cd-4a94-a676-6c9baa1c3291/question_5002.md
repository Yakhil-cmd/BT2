# Q5002: PR field `sender.login` missing-field exception halting

## Question
In the pull_request handlers, can an unprivileged PR author set `sender.login` (which is resolved through `User.find_or_create_by_login!` and becomes the acting review-stack `user`) such that it is required by the `ExplicitParameters` schema so omitting/retyping it raises during parse, breaking the assumption that a raised parse error is caught in a way that still?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `sender.login` in the webhook body (is resolved through `User.find_or_create_by_login!` and becomes the acting review-stack `user`)
- Exploit idea: the field is required by the `ExplicitParameters` schema so omitting/retyping it raises during parse; a raised parse error is caught in a way that still lets a partially-processed side effect land
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `sender.login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `sender.login`, assert which record was located/written and that it matches the intended repo+PR only.

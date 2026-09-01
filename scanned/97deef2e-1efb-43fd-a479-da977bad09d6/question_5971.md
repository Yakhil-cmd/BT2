# Q5971: PR field `pull_request.head.ref` missing-field exception halting

## Question
In the pull_request handlers, can an unprivileged PR author set `pull_request.head.ref` (which becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`) such that it is required by the `ExplicitParameters` schema so omitting/retyping it raises during parse, breaking the assumption that a raised parse error is caught in a way that still?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.head.ref` in the webhook body (becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`)
- Exploit idea: the field is required by the `ExplicitParameters` schema so omitting/retyping it raises during parse; a raised parse error is caught in a way that still lets a partially-processed side effect land
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `pull_request.head.ref` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `pull_request.head.ref`, assert which record was located/written and that it matches the intended repo+PR only.

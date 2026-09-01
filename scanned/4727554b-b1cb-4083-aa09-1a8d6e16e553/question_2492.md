# Q2492: PR field `repository.full_name` type confusion via loose schema

## Question
In the pull_request handlers, can an unprivileged PR author set `repository.full_name` (which selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`) such that it is declared with a permissive type so an array/hash/string coercion changes handler behaviour, breaking the assumption that the parsed value type equals what the handler logic assumes?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `repository.full_name` in the webhook body (selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`)
- Exploit idea: the field is declared with a permissive type so an array/hash/string coercion changes handler behaviour; the parsed value type equals what the handler logic assumes
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `repository.full_name` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `repository.full_name`, assert which record was located/written and that it matches the intended repo+PR only.

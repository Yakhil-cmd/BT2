# Q5763: PR field `repository.full_name` record-locator confusion

## Question
In the pull_request handlers, can an unprivileged PR author set `repository.full_name` (which selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`) such that it is used to locate the DB record (PullRequest/ReviewStack/Stack) the handler mutates, breaking the assumption that a mismatch?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/*.rb + app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `repository.full_name` in the webhook body (selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`)
- Exploit idea: the field is used to locate the DB record (PullRequest/ReviewStack/Stack) the handler mutates; a mismatch lets the handler mutate a record belonging to a different PR/stack/repository
- Invariant to test: The record a pull_request handler mutates is uniquely determined by, and belongs to, the repository+PR that authenticated the event; `repository.full_name` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a pull_request payload with a crafted `repository.full_name`, assert which record was located/written and that it matches the intended repo+PR only.

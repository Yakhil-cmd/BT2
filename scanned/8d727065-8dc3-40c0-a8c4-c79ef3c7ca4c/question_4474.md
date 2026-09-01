# Q4474: `repository.full_name` trust boundary in ReopenedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler`, can an unprivileged PR author craft `repository.full_name` (which selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`) so the handler, which unarchives / recreates a `ReviewStack` for the PR, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `repository.full_name` in the webhook body
- Exploit idea: `ReopenedHandler` consumes `repository.full_name` where it selects which repository's review stacks / stacks the handler writes to via `Repository.from_github_repo_name`; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `ReopenedHandler` mutates belongs to the repository+PR that authenticated the event; `repository.full_name` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `ReopenedHandler` with a hostile `repository.full_name`, assert the touched record is confined to the intended repo+PR.

# Q0361: `pull_request.assignees[].login` trust boundary in ReopenedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler`, can an unprivileged PR author craft `pull_request.assignees[].login` (which is stored as assignee identity) so the handler, which unarchives / recreates a `ReviewStack` for the PR, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.assignees[].login` in the webhook body
- Exploit idea: `ReopenedHandler` consumes `pull_request.assignees[].login` where it is stored as assignee identity; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `ReopenedHandler` mutates belongs to the repository+PR that authenticated the event; `pull_request.assignees[].login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `ReopenedHandler` with a hostile `pull_request.assignees[].login`, assert the touched record is confined to the intended repo+PR.

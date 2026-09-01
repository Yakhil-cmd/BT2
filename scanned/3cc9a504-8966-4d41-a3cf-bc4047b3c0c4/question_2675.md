# Q2675: `pull_request.head.ref` trust boundary in ReopenedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::ReopenedHandler`, can an unprivileged PR author craft `pull_request.head.ref` (which becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`) so the handler, which unarchives / recreates a `ReviewStack` for the PR, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/reopened_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.head.ref` in the webhook body
- Exploit idea: `ReopenedHandler` consumes `pull_request.head.ref` where it becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `ReopenedHandler` mutates belongs to the repository+PR that authenticated the event; `pull_request.head.ref` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `ReopenedHandler` with a hostile `pull_request.head.ref`, assert the touched record is confined to the intended repo+PR.

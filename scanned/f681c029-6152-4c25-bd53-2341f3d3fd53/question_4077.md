# Q4077: `pull_request.user.login` trust boundary in EditedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::EditedHandler`, can an unprivileged PR author craft `pull_request.user.login` (which is trusted as the PR author identity) so the handler, which updates the persisted `PullRequest` record from `params.pull_request`, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.user.login` in the webhook body
- Exploit idea: `EditedHandler` consumes `pull_request.user.login` where it is trusted as the PR author identity; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `EditedHandler` mutates belongs to the repository+PR that authenticated the event; `pull_request.user.login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `EditedHandler` with a hostile `pull_request.user.login`, assert the touched record is confined to the intended repo+PR.

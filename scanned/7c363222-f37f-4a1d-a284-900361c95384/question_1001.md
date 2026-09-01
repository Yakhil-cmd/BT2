# Q1001: `action` trust boundary in ClosedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler`, can an unprivileged PR author craft `action` (which selects which handler branch executes) so the handler, which archives the `ReviewStack` bound to the PR number, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `action` in the webhook body
- Exploit idea: `ClosedHandler` consumes `action` where it selects which handler branch executes; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `ClosedHandler` mutates belongs to the repository+PR that authenticated the event; `action` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `ClosedHandler` with a hostile `action`, assert the touched record is confined to the intended repo+PR.

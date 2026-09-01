# Q0379: `action` trust boundary in AssignedHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::AssignedHandler`, can an unprivileged PR author craft `action` (which selects which handler branch executes) so the handler, which updates the persisted `PullRequest` record on assignee change, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `action` in the webhook body
- Exploit idea: `AssignedHandler` consumes `action` where it selects which handler branch executes; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `AssignedHandler` mutates belongs to the repository+PR that authenticated the event; `action` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `AssignedHandler` with a hostile `action`, assert the touched record is confined to the intended repo+PR.

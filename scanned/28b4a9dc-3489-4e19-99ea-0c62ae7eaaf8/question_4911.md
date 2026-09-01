# Q4911: `number` trust boundary in LabeledHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::LabeledHandler`, can an unprivileged PR author craft `number` (which is the top-level PR number used to locate the record) so the handler, which archives or unarchives the review stack based on the provisioning label, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `number` in the webhook body
- Exploit idea: `LabeledHandler` consumes `number` where it is the top-level PR number used to locate the record; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `LabeledHandler` mutates belongs to the repository+PR that authenticated the event; `number` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `LabeledHandler` with a hostile `number`, assert the touched record is confined to the intended repo+PR.

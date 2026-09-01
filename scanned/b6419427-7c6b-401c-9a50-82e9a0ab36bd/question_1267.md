# Q1267: `pull_request.labels[].name` trust boundary in LabeledHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::LabeledHandler`, can an unprivileged PR author craft `pull_request.labels[].name` (which is persisted and uppercased into review-stack environment keys) so the handler, which archives or unarchives the review stack based on the provisioning label, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.labels[].name` in the webhook body
- Exploit idea: `LabeledHandler` consumes `pull_request.labels[].name` where it is persisted and uppercased into review-stack environment keys; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `LabeledHandler` mutates belongs to the repository+PR that authenticated the event; `pull_request.labels[].name` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `LabeledHandler` with a hostile `pull_request.labels[].name`, assert the touched record is confined to the intended repo+PR.

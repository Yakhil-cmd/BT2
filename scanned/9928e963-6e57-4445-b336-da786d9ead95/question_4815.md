# Q4815: `pull_request.head.ref` trust boundary in UnlabeledHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::UnlabeledHandler`, can an unprivileged PR author craft `pull_request.head.ref` (which becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`) so the handler, which archives or unarchives the review stack based on the provisioning label, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `pull_request.head.ref` in the webhook body
- Exploit idea: `UnlabeledHandler` consumes `pull_request.head.ref` where it becomes the review-stack `branch` checked out and built, via `ReviewStackAdapter#stack_attributes`; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `UnlabeledHandler` mutates belongs to the repository+PR that authenticated the event; `pull_request.head.ref` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `UnlabeledHandler` with a hostile `pull_request.head.ref`, assert the touched record is confined to the intended repo+PR.

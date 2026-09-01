# Q2473: `sender.login` trust boundary in LabelCapturingHandler

## Question
In `Shipit::Webhooks::Handlers::PullRequest::LabelCapturingHandler`, can an unprivileged PR author craft `sender.login` (which is resolved through `User.find_or_create_by_login!` and becomes the acting review-stack `user`) so the handler, which persists `params.pull_request.labels.map(&:name)` onto the review stack's `PullRequest`, and those names become uppercased environment keys in `ReviewStack#env`, acts on or writes a record for a repository/PR other than the one that authenticated the event?

## Target
- File/function: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create) (pull_request event)
- Attacker controls: `sender.login` in the webhook body
- Exploit idea: `LabelCapturingHandler` consumes `sender.login` where it is resolved through `User.find_or_create_by_login!` and becomes the acting review-stack `user`; combined with the provenance gap this crosses a repository boundary
- Invariant to test: The record `LabelCapturingHandler` mutates belongs to the repository+PR that authenticated the event; `sender.login` cannot redirect it.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: process a `pull_request` payload against `LabelCapturingHandler` with a hostile `sender.login`, assert the touched record is confined to the intended repo+PR.

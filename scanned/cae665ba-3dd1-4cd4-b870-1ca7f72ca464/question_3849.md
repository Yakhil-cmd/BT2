# Q3849: Forged `pull_request` closed webhook via unknown-organization error path reaches ClosedHandler

## Question
Can an unprivileged internet user POST a `pull_request` event (action=`closed`) to `/webhooks` that targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler` archives the `ReviewStack` bound to the PR number, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: pull_request` header, and `X-Hub-Signature`; specifically it targets `Shipit::GithubOrganizationUnknown` handling so a rescued error still leaves the request in a state the handler acts on
- Exploit idea: the `head(422)` on an unknown org actually halts the filter chain before `create` runs; the accepted body then drives `Shipit::Webhooks::Handlers::PullRequest::ClosedHandler` which archives the `ReviewStack` bound to the PR number
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `pull_request` body, assert the handler ran and mutated a record owned by a different org.

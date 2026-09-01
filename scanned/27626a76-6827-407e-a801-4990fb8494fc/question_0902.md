# Q0902: Forged `pull_request` edited webhook via no-secret organization reaches EditedHandler

## Question
Can an unprivileged internet user POST a `pull_request` event (action=`edited`) to `/webhooks` that sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::PullRequest::EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: pull_request` header, and `X-Hub-Signature`; specifically it sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; the accepted body then drives `Shipit::Webhooks::Handlers::PullRequest::EditedHandler` which updates the persisted `PullRequest` record from `params.pull_request`
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `pull_request` body, assert the handler ran and mutated a record owned by a different org.

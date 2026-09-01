# Q1487: Forged `push` webhook via no-secret organization reaches PushHandler

## Question
Can an unprivileged internet user POST a `push` event to `/webhooks` that sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`, so `WebhooksController#verify_signature` accepts it and `Shipit::Webhooks::Handlers::PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery, even though the attacker holds no `webhook_secret`?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the full JSON body, `X-Github-Event: push` header, and `X-Hub-Signature`; specifically it sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; the accepted body then drives `Shipit::Webhooks::Handlers::PushHandler` which syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery
- Invariant to test: The organization whose webhook_secret verified the request equals the organization that owns the repository/stack/commit/team the handler writes.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest ActionDispatch::IntegrationTest: configure one org with no webhook_secret, POST the crafted `push` body, assert the handler ran and mutated a record owned by a different org.

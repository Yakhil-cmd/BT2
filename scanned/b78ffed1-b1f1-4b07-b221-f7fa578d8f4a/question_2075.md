# Q2075: [no-secret organization] `push` -> PushHandler on a production environment stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `push` event against a victim stack where production environment, can an unprivileged attacker make `PushHandler` (syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery) cause impact because the affected stack is the production environment?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has production environment
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery; the affected stack is the production environment amplifies the effect
- Invariant to test: A `push` event only affects the repository/stack whose secret authenticated it, regardless of production environment.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `no-secret organization`, forge `push` for a production environment stack, assert the downstream effect.

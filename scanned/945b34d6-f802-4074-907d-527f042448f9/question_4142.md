# Q4142: [legacy sha1 signature header] `push` -> PushHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `push` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `PushHandler` (syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has bot_login configured (Shipit.user)
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `push` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `legacy sha1 signature header`, forge `push` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

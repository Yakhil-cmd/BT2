# Q2444: [legacy sha1 signature header] `pull_request` action=`assigned` -> AssignedHandler on a bot_login configured (Shipit.user) stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `pull_request` action=`assigned` event against a victim stack where bot_login configured (Shipit.user), can an unprivileged attacker make `AssignedHandler` (updates the persisted `PullRequest` record on assignee change) cause impact because auto-triggered deploys run as the configured bot identity?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/assigned_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`assigned`, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has bot_login configured (Shipit.user)
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `AssignedHandler` updates the persisted `PullRequest` record on assignee change; auto-triggered deploys run as the configured bot identity amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of bot_login configured (Shipit.user).
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `legacy sha1 signature header`, forge `pull_request` action=`assigned` for a bot_login configured (Shipit.user) stack, assert the downstream effect.

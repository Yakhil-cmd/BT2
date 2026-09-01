# Q0933: [legacy sha1 signature header] `status` -> StatusHandler on a continuous_deployment enabled stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `status` event against a victim stack where continuous_deployment enabled, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has continuous_deployment enabled
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; the victim stack auto-ships newly-green commits via ContinuousDeliveryJob amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `legacy sha1 signature header`, forge `status` for a continuous_deployment enabled stack, assert the downstream effect.

# Q5588: [legacy sha1 signature header] `status` -> StatusHandler on a blocking_statuses configured stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `status` event against a victim stack where blocking_statuses configured, can an unprivileged attacker make `StatusHandler` (runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all) cause impact because a forced status can set/clear `blocked?` and gate deploys?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/status_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `status` body, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has blocking_statuses configured
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `StatusHandler` runs `Commit.where(sha: params.sha).each { |c| c.create_status_from_github!(params) }` with no repository scoping at all; a forced status can set/clear `blocked?` and gate deploys amplifies the effect
- Invariant to test: A `status` event only affects the repository/stack whose secret authenticated it, regardless of blocking_statuses configured.
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: under `legacy sha1 signature header`, forge `status` for a blocking_statuses configured stack, assert the downstream effect.

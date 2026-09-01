# Q3888: [legacy sha1 signature header] `pull_request` action=`edited` -> EditedHandler on a ignore_ci true stack

## Question
Combining the `legacy sha1 signature header` verification gap (attacker supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`) with a `pull_request` action=`edited` event against a victim stack where ignore_ci true, can an unprivileged attacker make `EditedHandler` (updates the persisted `PullRequest` record from `params.pull_request`) cause impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/edited_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`edited`, signature/headers; supplies `X-Hub-Signature: sha1=...` (the only algorithm `verify_webhook_signature` accepts) rather than the modern `X-Hub-Signature-256`; victim stack has ignore_ci true
- Exploit idea: the code path that could reject a forged body depends on an algorithm/secret combination the attacker can sidestep for a no-secret org; `EditedHandler` updates the persisted `PullRequest` record from `params.pull_request`; `Commit#deployable?` short-circuits CI so any commit is shippable amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `legacy sha1 signature header`, forge `pull_request` action=`edited` for a ignore_ci true stack, assert the downstream effect.

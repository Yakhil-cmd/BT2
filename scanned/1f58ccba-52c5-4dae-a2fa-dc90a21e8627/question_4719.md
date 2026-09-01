# Q4719: [no-secret organization] `pull_request` action=`labeled` -> LabeledHandler on a continuous_deployment enabled stack

## Question
Combining the `no-secret organization` verification gap (attacker sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`) with a `pull_request` action=`labeled` event against a victim stack where continuous_deployment enabled, can an unprivileged attacker make `LabeledHandler` (archives or unarchives the review stack based on the provisioning label) cause impact because the victim stack auto-ships newly-green commits via ContinuousDeliveryJob?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`labeled`, signature/headers; sets `repository.owner.login` to a GitHub org that is configured in Shipit but whose config carries no `webhook_secret`; victim stack has continuous_deployment enabled
- Exploit idea: `GitHubApp#verify_webhook_signature` returns `true` immediately when `webhook_secret` is blank, so the forged body is accepted without any HMAC; `LabeledHandler` archives or unarchives the review stack based on the provisioning label; the victim stack auto-ships newly-green commits via ContinuousDeliveryJob amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of continuous_deployment enabled.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `no-secret organization`, forge `pull_request` action=`labeled` for a continuous_deployment enabled stack, assert the downstream effect.

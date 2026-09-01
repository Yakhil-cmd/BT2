# Q2874: [nil / malformed signature split] `pull_request` action=`unlabeled` -> UnlabeledHandler on a ignore_ci true stack

## Question
Combining the `nil / malformed signature split` verification gap (attacker sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`) with a `pull_request` action=`unlabeled` event against a victim stack where ignore_ci true, can an unprivileged attacker make `UnlabeledHandler` (archives or unarchives the review stack based on the provisioning label) cause impact because `Commit#deployable?` short-circuits CI so any commit is shippable?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/pull_request/unlabeled_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `pull_request` body action=`unlabeled`, signature/headers; sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`; victim stack has ignore_ci true
- Exploit idea: the comparison inputs are attacker-shaped and, for a no-secret org, never reached because verification short-circuits to true; `UnlabeledHandler` archives or unarchives the review stack based on the provisioning label; `Commit#deployable?` short-circuits CI so any commit is shippable amplifies the effect
- Invariant to test: A `pull_request` event only affects the repository/stack whose secret authenticated it, regardless of ignore_ci true.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: under `nil / malformed signature split`, forge `pull_request` action=`unlabeled` for a ignore_ci true stack, assert the downstream effect.

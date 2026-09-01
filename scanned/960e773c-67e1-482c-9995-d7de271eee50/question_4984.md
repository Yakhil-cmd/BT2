# Q4984: [nil / malformed signature split] `push` -> PushHandler on a review_stacks_enabled false stack

## Question
Combining the `nil / malformed signature split` verification gap (attacker sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`) with a `push` event against a victim stack where review_stacks_enabled false, can an unprivileged attacker make `PushHandler` (syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery) cause impact because review stacks are supposedly disabled yet the provision? precedence bug still provisions?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks/handlers/push_handler.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `push` body, signature/headers; sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`; victim stack has review_stacks_enabled false
- Exploit idea: the comparison inputs are attacker-shaped and, for a no-secret org, never reached because verification short-circuits to true; `PushHandler` syncs every non-archived stack on `params.ref` and calls `sync_github(expected_head_sha: params.after)`, which can append commits and drive continuous delivery; review stacks are supposedly disabled yet the provision? precedence bug still provisions amplifies the effect
- Invariant to test: A `push` event only affects the repository/stack whose secret authenticated it, regardless of review_stacks_enabled false.
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: under `nil / malformed signature split`, forge `push` for a review_stacks_enabled false stack, assert the downstream effect.

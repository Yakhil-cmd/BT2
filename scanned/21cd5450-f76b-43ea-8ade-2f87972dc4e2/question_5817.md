# Q5817: nil / malformed signature split -> insert the attacker into a monitored team

## Question
Chaining the `nil / malformed signature split` verification gap (attacker sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`) with a `membership` handler, can an unprivileged attacker insert the attacker into a monitored team on a repository they do not own?

## Target
- File/function: app/controllers/shipit/webhooks_controller.rb + lib/shipit/github_app.rb + app/models/shipit/webhooks.rb
- Entrypoint: Unauthenticated `POST /webhooks` (Shipit::WebhooksController#create)
- Attacker controls: the `membership` body plus signature/headers; sends `X-Hub-Signature` with no `=` so `signature.split('=',2)` yields `algorithm` = whole string and `signature` = nil into `SecureCompare.secure_compare`
- Exploit idea: the comparison inputs are attacker-shaped and, for a no-secret org, never reached because verification short-circuits to true, and the accepted `membership` event lets the attacker insert the attacker into a monitored team
- Invariant to test: A forged webhook cannot cause any state change attributed to a repository/org whose secret did not verify it.
- Expected Immunefi impact: High — Privilege escalation into Shipit.github_teams authorization
- Fast validation: minitest: forge the `membership` event under the `nil / malformed signature split` condition, assert the downstream mutation for the victim occurred.

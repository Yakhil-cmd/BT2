# Q5867: POST /webhooks: harvest a leaked ccmenu token from a URL

## Question
Using the unauthenticated/token-in-URL route `POST /webhooks` (Shipit::WebhooksController#create), can an unprivileged attacker harvest a leaked ccmenu token from a URL?

## Target
- File/function: route /webhooks
- Entrypoint: POST /webhooks (Shipit::WebhooksController#create)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because verify_signature + drop_unhandled_event run before create; both can be satisfied by an attacker for an org with no configured webhook_secret; the attacker leverages it to harvest a leaked ccmenu token from a URL
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `POST /webhooks` unauthenticated with crafted params, assert whether harvest succeeds.

# Q1881: POST /webhooks: enumerate existence of stacks by repo/branch

## Question
Using the unauthenticated/token-in-URL route `POST /webhooks` (Shipit::WebhooksController#create), can an unprivileged attacker enumerate existence of stacks by repo/branch?

## Target
- File/function: route /webhooks
- Entrypoint: POST /webhooks (Shipit::WebhooksController#create)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because verify_signature + drop_unhandled_event run before create; both can be satisfied by an attacker for an org with no configured webhook_secret; the attacker leverages it to enumerate existence of stacks by repo/branch
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `POST /webhooks` unauthenticated with crafted params, assert whether enumerate succeeds.

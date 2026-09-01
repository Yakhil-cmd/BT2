# Q1292: POST /webhooks: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `POST /webhooks` (Shipit::WebhooksController#create), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /webhooks
- Entrypoint: POST /webhooks (Shipit::WebhooksController#create)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because verify_signature + drop_unhandled_event run before create; both can be satisfied by an attacker for an org with no configured webhook_secret; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `POST /webhooks` unauthenticated with crafted params, assert whether frame succeeds.

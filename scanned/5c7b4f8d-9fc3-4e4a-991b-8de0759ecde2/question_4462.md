# Q4462: GET /events: read a private stack's merge/CI status

## Question
Using the unauthenticated/token-in-URL route `GET /events` (Pubsubstub::StreamAction), can an unprivileged attacker read a private stack's merge/CI status?

## Target
- File/function: route /events
- Entrypoint: GET /events (Pubsubstub::StreamAction)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because mounted inside the engine routes with no authentication concern in front of it; the attacker leverages it to read a private stack's merge/CI status
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /events` unauthenticated with crafted params, assert whether read succeeds.

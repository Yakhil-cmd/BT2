# Q0646: GET /events: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `GET /events` (Pubsubstub::StreamAction), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /events
- Entrypoint: GET /events (Pubsubstub::StreamAction)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because mounted inside the engine routes with no authentication concern in front of it; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /events` unauthenticated with crafted params, assert whether frame succeeds.

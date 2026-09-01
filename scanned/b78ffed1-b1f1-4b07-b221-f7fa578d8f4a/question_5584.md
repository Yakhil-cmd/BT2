# Q5584: GET /status/version: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `GET /status/version` (Shipit::StatusController#version), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /status/version
- Entrypoint: GET /status/version (Shipit::StatusController#version)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because bare ActionController::Base with no authentication, renders `Shipit.revision`; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /status/version` unauthenticated with crafted params, assert whether frame succeeds.

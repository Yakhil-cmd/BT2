# Q3733: PUT /merge_status/*stack_id/pull/:number: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `PUT /merge_status/*stack_id/pull/:number` (Shipit::MergeStatusController#enqueue), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /merge_status/*stack_id/pull/:number
- Entrypoint: PUT /merge_status/*stack_id/pull/:number (Shipit::MergeStatusController#enqueue)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because enqueue is NOT in the skip list but the show/check surface leaks state and the ALLOWALL header enables framing a logged-in victim; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `PUT /merge_status/*stack_id/pull/:number` unauthenticated with crafted params, assert whether frame succeeds.

# Q0846: PUT /merge_status/*stack_id/pull/:number: stream another tenant's live task output

## Question
Using the unauthenticated/token-in-URL route `PUT /merge_status/*stack_id/pull/:number` (Shipit::MergeStatusController#enqueue), can an unprivileged attacker stream another tenant's live task output?

## Target
- File/function: route /merge_status/*stack_id/pull/:number
- Entrypoint: PUT /merge_status/*stack_id/pull/:number (Shipit::MergeStatusController#enqueue)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because enqueue is NOT in the skip list but the show/check surface leaks state and the ALLOWALL header enables framing a logged-in victim; the attacker leverages it to stream another tenant's live task output
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `PUT /merge_status/*stack_id/pull/:number` unauthenticated with crafted params, assert whether stream succeeds.

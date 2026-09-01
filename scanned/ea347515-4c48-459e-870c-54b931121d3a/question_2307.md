# Q2307: GET /merge_status: enumerate existence of stacks by repo/branch

## Question
Using the unauthenticated/token-in-URL route `GET /merge_status` (Shipit::MergeStatusController#show), can an unprivileged attacker enumerate existence of stacks by repo/branch?

## Target
- File/function: route /merge_status
- Entrypoint: GET /merge_status (Shipit::MergeStatusController#show)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because `skip_authentication only: %i[check show]`; stack derived from `params[:referrer]` via `ReferrerParser`; sets `X-Frame-Options: ALLOWALL`; the attacker leverages it to enumerate existence of stacks by repo/branch
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /merge_status` unauthenticated with crafted params, assert whether enumerate succeeds.

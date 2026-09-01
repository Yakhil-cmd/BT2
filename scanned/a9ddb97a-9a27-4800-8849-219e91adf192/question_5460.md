# Q5460: GET /merge_status: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `GET /merge_status` (Shipit::MergeStatusController#show), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /merge_status
- Entrypoint: GET /merge_status (Shipit::MergeStatusController#show)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because `skip_authentication only: %i[check show]`; stack derived from `params[:referrer]` via `ReferrerParser`; sets `X-Frame-Options: ALLOWALL`; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /merge_status` unauthenticated with crafted params, assert whether frame succeeds.

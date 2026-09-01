# Q4426: GET /api/stacks/*stack_id/ccmenu: enumerate existence of stacks by repo/branch

## Question
Using the unauthenticated/token-in-URL route `GET /api/stacks/*stack_id/ccmenu` (Shipit::Api::CCMenuController#show), can an unprivileged attacker enumerate existence of stacks by repo/branch?

## Target
- File/function: route /api/stacks/*stack_id/ccmenu
- Entrypoint: GET /api/stacks/*stack_id/ccmenu (Shipit::Api::CCMenuController#show)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because overrides `authenticate_api_client` to accept `ApiClient.authenticate(params[:token])` from the query string; the attacker leverages it to enumerate existence of stacks by repo/branch
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /api/stacks/*stack_id/ccmenu` unauthenticated with crafted params, assert whether enumerate succeeds.

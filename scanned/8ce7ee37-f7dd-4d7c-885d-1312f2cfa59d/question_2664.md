# Q2664: GET /api/stacks/*stack_id/ccmenu: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `GET /api/stacks/*stack_id/ccmenu` (Shipit::Api::CCMenuController#show), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /api/stacks/*stack_id/ccmenu
- Entrypoint: GET /api/stacks/*stack_id/ccmenu (Shipit::Api::CCMenuController#show)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because overrides `authenticate_api_client` to accept `ApiClient.authenticate(params[:token])` from the query string; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET /api/stacks/*stack_id/ccmenu` unauthenticated with crafted params, assert whether frame succeeds.

# Q1953: DELETE /api/stacks/*id: ccmenu token in query string

## Question
On `DELETE /api/stacks/*id` (destroy), can an unprivileged attacker exploit that `Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token to act outside a token's stack scope or permission, breaking that a read:stack token placed in a URL leaks via Referer/logs/history and then authenticates ccmenu for a stack?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: DELETE /api/stacks/*id (destroy)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token, so a read:stack token placed in a URL leaks via Referer/logs/history and then authenticates ccmenu for a stack may fail on `DELETE /api/stacks/*id`
- Invariant to test: `DELETE /api/stacks/*id` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: call `DELETE /api/stacks/*id` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

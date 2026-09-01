# Q5998: API auth weakness: ccmenu token in query string

## Question
Can an unprivileged attacker abuse that `Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token to read or act on a stack outside a token's scope, or to misattribute an action, breaking the assumption that a read:stack token placed in a URL leaks via Referer/logs/history and then authenticates ccmenu for a stack?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/ccmenu_controller.rb + app/models/shipit/api_client.rb + app/controllers/shipit/ccmenu_url_controller.rb
- Entrypoint: Shipit::Api::* endpoints (basic-auth or ?token=) / GET /api/stacks/*stack_id/ccmenu
- Attacker controls: the token param/header and the target stack_id (`Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token)
- Exploit idea: a read:stack token placed in a URL leaks via Referer/logs/history and then authenticates ccmenu for a stack is the assumption; the code path `Api::CCMenuController#authenticate_api_client` accepts `ApiClient.authenticate(params[:token])`, and `CCMenuUrlController#fetch` hands out a URL embedding that token
- Invariant to test: An API request only touches stacks its ApiClient stack_id authorizes, the checked permission equals the action's requirement, and the recorded actor equals the authenticated principal.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: create a stack-scoped read:stack ApiClient, call the endpoint for a DIFFERENT stack (via ?token= or X-Shipit-User), assert it is rejected.

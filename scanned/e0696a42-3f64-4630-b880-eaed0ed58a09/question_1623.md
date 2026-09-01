# Q1623: API auth weakness: stack scope not enforced on ccmenu

## Question
Can an unprivileged attacker abuse that `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation to read or act on a stack outside a token's scope, or to misattribute an action, breaking the assumption that a stack-scoped ccmenu token can only read the stack it is scoped to?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/ccmenu_controller.rb + app/models/shipit/api_client.rb + app/controllers/shipit/ccmenu_url_controller.rb
- Entrypoint: Shipit::Api::* endpoints (basic-auth or ?token=) / GET /api/stacks/*stack_id/ccmenu
- Attacker controls: the token param/header and the target stack_id (`Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation)
- Exploit idea: a stack-scoped ccmenu token can only read the stack it is scoped to is the assumption; the code path `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation
- Invariant to test: An API request only touches stacks its ApiClient stack_id authorizes, the checked permission equals the action's requirement, and the recorded actor equals the authenticated principal.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: create a stack-scoped read:stack ApiClient, call the endpoint for a DIFFERENT stack (via ?token= or X-Shipit-User), assert it is rejected.

# Q3959: POST /api/stacks/*id/refresh: stack scope not enforced on ccmenu

## Question
On `POST /api/stacks/*id/refresh` (refresh), can an unprivileged attacker exploit that `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation to act outside a token's stack scope or permission, breaking that a stack-scoped ccmenu token can only read the stack it is scoped to?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: POST /api/stacks/*id/refresh (refresh)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation, so a stack-scoped ccmenu token can only read the stack it is scoped to may fail on `POST /api/stacks/*id/refresh`
- Invariant to test: `POST /api/stacks/*id/refresh` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: call `POST /api/stacks/*id/refresh` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

# Q0826: GET /api/stacks: stack scope not enforced on ccmenu

## Question
On `GET /api/stacks` (index), can an unprivileged attacker exploit that `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation to act outside a token's stack scope or permission, breaking that a stack-scoped ccmenu token can only read the stack it is scoped to?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: GET /api/stacks (index)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` directly instead of the token-scoped `stacks` relation, so a stack-scoped ccmenu token can only read the stack it is scoped to may fail on `GET /api/stacks`
- Invariant to test: `GET /api/stacks` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: call `GET /api/stacks` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

# Q5806: PUT /api/stacks/*stack_id/tasks/:id/abort: message verifier decimal-id forgery

## Question
On `PUT /api/stacks/*stack_id/tasks/:id/abort` (tasks#abort), can an unprivileged attacker exploit that targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id to act outside a token's stack scope or permission, breaking that a token's id component cannot be altered without invalidating the signature?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: PUT /api/stacks/*stack_id/tasks/:id/abort (tasks#abort)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id, so a token's id component cannot be altered without invalidating the signature may fail on `PUT /api/stacks/*stack_id/tasks/:id/abort`
- Invariant to test: `PUT /api/stacks/*stack_id/tasks/:id/abort` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: call `PUT /api/stacks/*stack_id/tasks/:id/abort` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

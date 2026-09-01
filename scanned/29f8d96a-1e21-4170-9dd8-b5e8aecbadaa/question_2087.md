# Q2087: POST /api/stacks/*stack_id/rollbacks: message verifier decimal-id forgery

## Question
On `POST /api/stacks/*stack_id/rollbacks` (rollbacks#create), can an unprivileged attacker exploit that targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id to act outside a token's stack scope or permission, breaking that a token's id component cannot be altered without invalidating the signature?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: POST /api/stacks/*stack_id/rollbacks (rollbacks#create)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id, so a token's id component cannot be altered without invalidating the signature may fail on `POST /api/stacks/*stack_id/rollbacks`
- Invariant to test: `POST /api/stacks/*stack_id/rollbacks` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: call `POST /api/stacks/*stack_id/rollbacks` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

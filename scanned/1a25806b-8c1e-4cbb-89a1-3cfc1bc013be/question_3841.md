# Q3841: GET /api/stacks: message verifier decimal-id forgery

## Question
On `GET /api/stacks` (index), can an unprivileged attacker exploit that targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id to act outside a token's stack scope or permission, breaking that a token's id component cannot be altered without invalidating the signature?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: GET /api/stacks (index)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id, so a token's id component cannot be altered without invalidating the signature may fail on `GET /api/stacks`
- Invariant to test: `GET /api/stacks` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: call `GET /api/stacks` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

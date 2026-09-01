# Q0565: POST /api/hooks: X-Shipit-User attribution spoof

## Question
On `POST /api/hooks` (hooks#create), can an unprivileged attacker exploit that `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client to act outside a token's stack scope or permission, breaking that the actor recorded for an API-triggered deploy/lock equals the authenticated principal?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: POST /api/hooks (hooks#create)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client, so the actor recorded for an API-triggered deploy/lock equals the authenticated principal may fail on `POST /api/hooks`
- Invariant to test: `POST /api/hooks` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: call `POST /api/hooks` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

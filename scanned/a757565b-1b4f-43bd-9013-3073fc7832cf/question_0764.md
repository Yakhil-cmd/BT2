# Q0764: PUT /api/stacks/*stack_id/merge_requests/:id: X-Shipit-User attribution spoof

## Question
On `PUT /api/stacks/*stack_id/merge_requests/:id` (merge_requests#update), can an unprivileged attacker exploit that `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client to act outside a token's stack scope or permission, breaking that the actor recorded for an API-triggered deploy/lock equals the authenticated principal?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: PUT /api/stacks/*stack_id/merge_requests/:id (merge_requests#update)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client, so the actor recorded for an API-triggered deploy/lock equals the authenticated principal may fail on `PUT /api/stacks/*stack_id/merge_requests/:id`
- Invariant to test: `PUT /api/stacks/*stack_id/merge_requests/:id` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: call `PUT /api/stacks/*stack_id/merge_requests/:id` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

# Q3765: GET /api/stacks/*stack_id/ccmenu: basic-auth part joining

## Question
On `GET /api/stacks/*stack_id/ccmenu` (ccmenu#show), can an unprivileged attacker exploit that `authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate` to act outside a token's stack scope or permission, breaking that the reconstructed token equals exactly the issued token and cannot be satisfied by an alternate username/password split?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: GET /api/stacks/*stack_id/ccmenu (ccmenu#show)
- Attacker controls: the token (basic-auth or ?token=), X-Shipit-User header, and stack_id path (`authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate`)
- Exploit idea: `require_permission!` and the token-scoped `stacks` relation are the only guards; `authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate`, so the reconstructed token equals exactly the issued token and cannot be satisfied by an alternate username/password split may fail on `GET /api/stacks/*stack_id/ccmenu`
- Invariant to test: `GET /api/stacks/*stack_id/ccmenu` only succeeds for a token scoped to that stack with the required permission, attributed to the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: call `GET /api/stacks/*stack_id/ccmenu` with a mis-scoped/insufficient token (or via ?token= / X-Shipit-User), assert rejection.

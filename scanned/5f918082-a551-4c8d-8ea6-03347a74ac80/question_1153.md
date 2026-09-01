# Q1153: API auth weakness: basic-auth part joining

## Question
Can an unprivileged attacker abuse that `authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate` to read or act on a stack outside a token's scope, or to misattribute an action, breaking the assumption that the reconstructed token equals exactly the issued token and cannot be satisfied by an alternate username/password split?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/ccmenu_controller.rb + app/models/shipit/api_client.rb + app/controllers/shipit/ccmenu_url_controller.rb
- Entrypoint: Shipit::Api::* endpoints (basic-auth or ?token=) / GET /api/stacks/*stack_id/ccmenu
- Attacker controls: the token param/header and the target stack_id (`authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate`)
- Exploit idea: the reconstructed token equals exactly the issued token and cannot be satisfied by an alternate username/password split is the assumption; the code path `authenticate_api_client` joins parts with `parts.select(&:present?).join('--')` before `ApiClient.authenticate`
- Invariant to test: An API request only touches stacks its ApiClient stack_id authorizes, the checked permission equals the action's requirement, and the recorded actor equals the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: create a stack-scoped read:stack ApiClient, call the endpoint for a DIFFERENT stack (via ?token= or X-Shipit-User), assert it is rejected.

# Q4061: API auth weakness: message verifier decimal-id forgery

## Question
Can an unprivileged attacker abuse that targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id to read or act on a stack outside a token's scope, or to misattribute an action, breaking the assumption that a token's id component cannot be altered without invalidating the signature?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/ccmenu_controller.rb + app/models/shipit/api_client.rb + app/controllers/shipit/ccmenu_url_controller.rb
- Entrypoint: Shipit::Api::* endpoints (basic-auth or ?token=) / GET /api/stacks/*stack_id/ccmenu
- Attacker controls: the token param/header and the target stack_id (targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id)
- Exploit idea: a token's id component cannot be altered without invalidating the signature is the assumption; the code path targets `SimpleMessageVerifier` (ActiveSupport::MessageVerifier with a to_s serializer) whose payload is a decimal id
- Invariant to test: An API request only touches stacks its ApiClient stack_id authorizes, the checked permission equals the action's requirement, and the recorded actor equals the authenticated principal.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest: create a stack-scoped read:stack ApiClient, call the endpoint for a DIFFERENT stack (via ?token= or X-Shipit-User), assert it is rejected.

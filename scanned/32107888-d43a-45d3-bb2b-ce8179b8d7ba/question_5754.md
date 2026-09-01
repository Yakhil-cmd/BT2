# Q5754: API auth weakness: X-Shipit-User attribution spoof

## Question
Can an unprivileged attacker abuse that `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client to read or act on a stack outside a token's scope, or to misattribute an action, breaking the assumption that the actor recorded for an API-triggered deploy/lock equals the authenticated principal?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/ccmenu_controller.rb + app/models/shipit/api_client.rb + app/controllers/shipit/ccmenu_url_controller.rb
- Entrypoint: Shipit::Api::* endpoints (basic-auth or ?token=) / GET /api/stacks/*stack_id/ccmenu
- Attacker controls: the token param/header and the target stack_id (`Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client)
- Exploit idea: the actor recorded for an API-triggered deploy/lock equals the authenticated principal is the assumption; the code path `Api::BaseController#identify_user` trusts the `X-Shipit-User` header for `current_user` while permissions are only checked on the client
- Invariant to test: An API request only touches stacks its ApiClient stack_id authorizes, the checked permission equals the action's requirement, and the recorded actor equals the authenticated principal.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: create a stack-scoped read:stack ApiClient, call the endpoint for a DIFFERENT stack (via ?token= or X-Shipit-User), assert it is rejected.

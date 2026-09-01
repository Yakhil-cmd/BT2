# Q3514: Unauthenticated surface: merge_status unauthenticated state read

## Question
Can an unprivileged attacker use that GET /merge_status with a crafted `referrer` (and `branch`) reads a stack's merge status without a session (`skip_authentication`), violating the invariant that stack merge/CI state is only disclosed to authenticated, authorized users?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (GET /merge_status with a crafted `referrer` (and `branch`) reads a stack's merge status without a session (`skip_authentication`))
- Exploit idea: stack merge/CI state is only disclosed to authenticated, authorized users is the invariant; the surface GET /merge_status with a crafted `referrer` (and `branch`) reads a stack's merge status without a session (`skip_authentication`)
- Invariant to test: stack merge/CI state is only disclosed to authenticated, authorized users
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

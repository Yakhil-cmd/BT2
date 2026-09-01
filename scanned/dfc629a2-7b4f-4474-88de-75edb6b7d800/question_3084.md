# Q3084: Unauthenticated surface: task output secret disclosure

## Question
Can an unprivileged attacker use that unauthenticated or cross-tenant access to `Task#chunk_output` / `tail` / `.txt` rendering exposes deploy logs where interpolated commands print, violating the invariant that deploy output containing tokens/secrets is only visible to authorized users of that stack?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (unauthenticated or cross-tenant access to `Task#chunk_output` / `tail` / `.txt` rendering exposes deploy logs where interpolated commands print)
- Exploit idea: deploy output containing tokens/secrets is only visible to authorized users of that stack is the invariant; the surface unauthenticated or cross-tenant access to `Task#chunk_output` / `tail` / `.txt` rendering exposes deploy logs where interpolated commands print
- Invariant to test: deploy output containing tokens/secrets is only visible to authorized users of that stack
- Expected Immunefi impact: Critical — Exfiltration of GITHUB_TOKEN / a user's github_access_token / deploy-time secrets
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

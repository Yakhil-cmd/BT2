# Q1457: Unauthenticated surface: /events stream without auth

## Question
Can an unprivileged attacker use that GET /events (Pubsubstub) is mounted in the engine routes with no authentication concern, potentially streaming task/deploy events, violating the invariant that live task/deploy event streams require authentication?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (GET /events (Pubsubstub) is mounted in the engine routes with no authentication concern, potentially streaming task/deploy events)
- Exploit idea: live task/deploy event streams require authentication is the invariant; the surface GET /events (Pubsubstub) is mounted in the engine routes with no authentication concern, potentially streaming task/deploy events
- Invariant to test: live task/deploy event streams require authentication
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

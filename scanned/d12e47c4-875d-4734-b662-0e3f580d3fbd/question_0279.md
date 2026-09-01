# Q0279: Unauthenticated surface: clickjacking into merge enqueue

## Question
Can an unprivileged attacker use that `MergeStatusController#show` sets `X-Frame-Options: ALLOWALL`, and the enqueue/dequeue PUT/DELETE routes change merge-queue state, violating the invariant that state-changing merge-queue actions cannot be driven by framing a logged-in victim?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (`MergeStatusController#show` sets `X-Frame-Options: ALLOWALL`, and the enqueue/dequeue PUT/DELETE routes change merge-queue state)
- Exploit idea: state-changing merge-queue actions cannot be driven by framing a logged-in victim is the invariant; the surface `MergeStatusController#show` sets `X-Frame-Options: ALLOWALL`, and the enqueue/dequeue PUT/DELETE routes change merge-queue state
- Invariant to test: state-changing merge-queue actions cannot be driven by framing a logged-in victim
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

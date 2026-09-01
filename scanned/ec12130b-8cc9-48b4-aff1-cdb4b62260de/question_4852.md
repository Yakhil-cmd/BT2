# Q4852: Unauthenticated surface: SameSite=None cookie widening

## Question
Can an unprivileged attacker use that `SameSiteCookieMiddleware` rewrites every cookie to `SameSite=None` when enabled, enabling cross-site cookie attachment, violating the invariant that session cookies are not sent on cross-site requests that could change state?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (`SameSiteCookieMiddleware` rewrites every cookie to `SameSite=None` when enabled, enabling cross-site cookie attachment)
- Exploit idea: session cookies are not sent on cross-site requests that could change state is the invariant; the surface `SameSiteCookieMiddleware` rewrites every cookie to `SameSite=None` when enabled, enabling cross-site cookie attachment
- Invariant to test: session cookies are not sent on cross-site requests that could change state
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

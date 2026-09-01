# Q2358: Unauthenticated surface: hook delivery_url SSRF (no_local validator)

## Question
Can an unprivileged attacker use that `Hook`/`Delivery` validate `delivery_url` with `url: { no_local: true, allow_blank: true }`; if a webhook/PR path can register or redirect a delivery, the app posts signed payloads to an attacker URL, violating the invariant that outbound hook deliveries only reach operator-approved destinations and never internal addresses?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (`Hook`/`Delivery` validate `delivery_url` with `url: { no_local: true, allow_blank: true }`; if a webhook/PR path can register or redirect a delivery, the app posts signed payloads to an attacker URL)
- Exploit idea: outbound hook deliveries only reach operator-approved destinations and never internal addresses is the invariant; the surface `Hook`/`Delivery` validate `delivery_url` with `url: { no_local: true, allow_blank: true }`; if a webhook/PR path can register or redirect a delivery, the app posts signed payloads to an attacker URL
- Invariant to test: outbound hook deliveries only reach operator-approved destinations and never internal addresses
- Expected Immunefi impact: High — SSRF issuing requests carrying the app's GitHub credentials
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

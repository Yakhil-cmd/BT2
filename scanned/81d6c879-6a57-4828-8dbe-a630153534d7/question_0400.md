# Q0400: Unauthenticated surface: deploy_url scheme via ssh

## Question
Can an unprivileged attacker use that `Stack` validates `deploy_url` allowing `ssh` scheme; if surfaced into a command or link it may be abused, violating the invariant that a stack deploy_url cannot introduce an unexpected scheme into an executed command or outbound request?

## Target
- File/function: app/controllers/shipit/merge_status_controller.rb + config/routes.rb + lib/shipit/engine.rb + app/models/shipit/hook.rb + lib/shipit/same_site_cookie_middleware.rb
- Entrypoint: Unauthenticated engine routes (/merge_status, /events, /status/version) and hook delivery
- Attacker controls: the request params/headers and any registerable delivery URL (`Stack` validates `deploy_url` allowing `ssh` scheme; if surfaced into a command or link it may be abused)
- Exploit idea: a stack deploy_url cannot introduce an unexpected scheme into an executed command or outbound request is the invariant; the surface `Stack` validates `deploy_url` allowing `ssh` scheme; if surfaced into a command or link it may be abused
- Invariant to test: a stack deploy_url cannot introduce an unexpected scheme into an executed command or outbound request
- Expected Immunefi impact: High — SSRF issuing requests carrying the app's GitHub credentials
- Fast validation: minitest ActionDispatch::IntegrationTest: issue the unauthenticated request (or trigger the delivery), assert the response body / outbound request / header exposes what the invariant forbids.

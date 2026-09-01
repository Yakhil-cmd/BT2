# Q1710: OAuth session weakness: open-redirect via omniauth.origin

## Question
Can an unprivileged attacker who controls `request.env['omniauth.origin']` (seeded from `origin=` on the auth request) so the post-login redirect goes to an attacker URL obtain an authenticated Shipit session bound to a victim (or to an identity that is not theirs), violating that the post-authentication redirect target is a same-origin Shipit path?

## Target
- File/function: app/controllers/shipit/github_authentication_controller.rb + app/controllers/concerns/shipit/authentication.rb
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: the pre-login session cookie, the `origin=` param, and cross-site request timing (controls `request.env['omniauth.origin']` (seeded from `origin=` on the auth request) so the post-login redirect goes to an attacker URL)
- Exploit idea: `callback` assigns session identity without reset_session and redirects to an unfiltered origin; the post-authentication redirect target is a same-origin Shipit path is not enforced
- Invariant to test: session[:user_id] equals the GitHub account that completed this OAuth exchange in this exact session.
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: simulate the omniauth env, assert session id rotation, redirect target, and the resolved User identity.

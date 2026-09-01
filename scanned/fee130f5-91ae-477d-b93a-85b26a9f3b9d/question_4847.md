# Q4847: OAuth session weakness: GET-routed callback CSRF

## Question
Can an unprivileged attacker who completes the OAuth callback cross-site because it is routed for GET and the controller has no `protect_from_forgery` obtain an authenticated Shipit session bound to a victim (or to an identity that is not theirs), violating that a state-changing login can only be completed by a same-site request the user intended?

## Target
- File/function: app/controllers/shipit/github_authentication_controller.rb + app/controllers/concerns/shipit/authentication.rb
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: the pre-login session cookie, the `origin=` param, and cross-site request timing (completes the OAuth callback cross-site because it is routed for GET and the controller has no `protect_from_forgery`)
- Exploit idea: `callback` assigns session identity without reset_session and redirects to an unfiltered origin; a state-changing login can only be completed by a same-site request the user intended is not enforced
- Invariant to test: session[:user_id] equals the GitHub account that completed this OAuth exchange in this exact session.
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: simulate the omniauth env, assert session id rotation, redirect target, and the resolved User identity.

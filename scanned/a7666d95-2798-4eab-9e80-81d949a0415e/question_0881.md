# Q0881: OAuth session weakness: no reset_session before assignment

## Question
Can an unprivileged attacker who plants a known session (session fixation) then has the victim complete GitHub login, since `callback` sets `session[:user_id]`/`session[:authenticated]` without `reset_session` obtain an authenticated Shipit session bound to a victim (or to an identity that is not theirs), violating that the session id before and after authentication differ?

## Target
- File/function: app/controllers/shipit/github_authentication_controller.rb + app/controllers/concerns/shipit/authentication.rb
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: the pre-login session cookie, the `origin=` param, and cross-site request timing (plants a known session (session fixation) then has the victim complete GitHub login, since `callback` sets `session[:user_id]`/`session[:authenticated]` without `reset_session`)
- Exploit idea: `callback` assigns session identity without reset_session and redirects to an unfiltered origin; the session id before and after authentication differ is not enforced
- Invariant to test: session[:user_id] equals the GitHub account that completed this OAuth exchange in this exact session.
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: simulate the omniauth env, assert session id rotation, redirect target, and the resolved User identity.

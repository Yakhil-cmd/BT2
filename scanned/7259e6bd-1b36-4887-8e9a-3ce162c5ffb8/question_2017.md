# Q2017: OAuth session weakness: identity aliasing find_or_create_by_login!

## Question
Can an unprivileged attacker who uses a login vs github_id mismatch so `find_current_user`/`find_or_create_from_github` resolves `session[:user_id]` to a different User row than the GitHub account that authenticated obtain an authenticated Shipit session bound to a victim (or to an identity that is not theirs), violating that session[:user_id] names the exact GitHub account that completed this OAuth exchange?

## Target
- File/function: app/controllers/shipit/github_authentication_controller.rb + app/controllers/concerns/shipit/authentication.rb
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: the pre-login session cookie, the `origin=` param, and cross-site request timing (uses a login vs github_id mismatch so `find_current_user`/`find_or_create_from_github` resolves `session[:user_id]` to a different User row than the GitHub account that authenticated)
- Exploit idea: `callback` assigns session identity without reset_session and redirects to an unfiltered origin; session[:user_id] names the exact GitHub account that completed this OAuth exchange is not enforced
- Invariant to test: session[:user_id] equals the GitHub account that completed this OAuth exchange in this exact session.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest ActionDispatch::IntegrationTest: simulate the omniauth env, assert session id rotation, redirect target, and the resolved User identity.

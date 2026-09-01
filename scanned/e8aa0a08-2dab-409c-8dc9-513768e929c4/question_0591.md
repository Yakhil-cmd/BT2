# Q0591: OAuth session weakness: requires_fresh_login regex bypass

## Question
Can an unprivileged attacker who supplies a `github_access_token` shaped to pass `GITHUB_TOKEN_FORMAT = /^gh[a-z]_/` so `requires_fresh_login?` never forces re-auth obtain an authenticated Shipit session bound to a victim (or to an identity that is not theirs), violating that a stale/invalid token forces a fresh login rather than being silently accepted?

## Target
- File/function: app/controllers/shipit/github_authentication_controller.rb + app/controllers/concerns/shipit/authentication.rb
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: the pre-login session cookie, the `origin=` param, and cross-site request timing (supplies a `github_access_token` shaped to pass `GITHUB_TOKEN_FORMAT = /^gh[a-z]_/` so `requires_fresh_login?` never forces re-auth)
- Exploit idea: `callback` assigns session identity without reset_session and redirects to an unfiltered origin; a stale/invalid token forces a fresh login rather than being silently accepted is not enforced
- Invariant to test: session[:user_id] equals the GitHub account that completed this OAuth exchange in this exact session.
- Expected Immunefi impact: Critical — Authentication/authorization bypass (forged webhook or session accepted as trusted)
- Fast validation: minitest ActionDispatch::IntegrationTest: simulate the omniauth env, assert session id rotation, redirect target, and the resolved User identity.

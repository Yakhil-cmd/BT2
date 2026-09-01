# Q0311: GET/POST /github/auth/github/callback: frame a logged-in operator into a state change

## Question
Using the unauthenticated/token-in-URL route `GET/POST /github/auth/github/callback` (Shipit::GithubAuthenticationController#callback), can an unprivileged attacker frame a logged-in operator into a state change?

## Target
- File/function: route /github/auth/github/callback
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because ActionController::Base with no protect_from_forgery; sets session without reset_session; redirects to omniauth.origin; the attacker leverages it to frame a logged-in operator into a state change
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET/POST /github/auth/github/callback` unauthenticated with crafted params, assert whether frame succeeds.

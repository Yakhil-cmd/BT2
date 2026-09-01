# Q4329: GET/POST /github/auth/github/callback: enumerate existence of stacks by repo/branch

## Question
Using the unauthenticated/token-in-URL route `GET/POST /github/auth/github/callback` (Shipit::GithubAuthenticationController#callback), can an unprivileged attacker enumerate existence of stacks by repo/branch?

## Target
- File/function: route /github/auth/github/callback
- Entrypoint: GET/POST /github/auth/github/callback (Shipit::GithubAuthenticationController#callback)
- Attacker controls: request params, headers, cookies, and any token embedded in the URL
- Exploit idea: the route is reachable without a Shipit session because ActionController::Base with no protect_from_forgery; sets session without reset_session; redirects to omniauth.origin; the attacker leverages it to enumerate existence of stacks by repo/branch
- Invariant to test: Every stack/task/output disclosure and every state change is gated by force_github_authentication + authorized? (or a correctly-scoped token).
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest ActionDispatch::IntegrationTest: hit `GET/POST /github/auth/github/callback` unauthenticated with crafted params, assert whether enumerate succeeds.

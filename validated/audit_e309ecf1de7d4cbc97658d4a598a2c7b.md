This confirms the vulnerability. The `callback` action indeed never calls `reset_session` before writing `session[:user_id]` and `session[:authenticated]`, unlike the sibling `logout` action and `force_github_authentication`'s stale-login handling, both of which explicitly call `reset_session`.### Title
Session fixation in OAuth callback due to missing `reset_session` before establishing authenticated session - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`Shipit::GithubAuthenticationController#callback` writes `session[:user_id]` and `session[:authenticated] = true` directly onto whatever session ID the browser presented, without ever calling `reset_session`. This lets an attacker who plants a session ID in a victim's browser (session fixation) inherit the victim's authenticated session once the victim completes the real GitHub OAuth handshake on that pre-existing session.

### Finding Description
The broken binding, stated explicitly: `session.id(before callback) == session.id(after callback)` — this equality holds in the current code, but for the authentication transition to be safe it MUST NOT hold (Rails should rotate the session id on privilege escalation).

Code path: [1](#0-0)  shows `callback` reading `omniauth.origin`/`omniauth.auth` from `request.env`, then unconditionally executing `session[:user_id] = sign_in_github(auth)` followed by `session[:authenticated] = true` on the same session id, then redirecting. No `reset_session` call exists anywhere in this method.

Contrast with the rest of the engine, which does treat `reset_session` as the correct primitive for session-identity transitions: `logout` calls `reset_session` before redirecting [2](#0-1) , and `force_github_authentication` calls `reset_session` when forcing a stale user to re-authenticate [3](#0-2) . The omission specifically in the successful-login path is the root cause.

`current_user`/`find_current_user` trust `session[:user_id]` alone to resolve identity [4](#0-3) , so whoever controls the session cookie value at the time `callback` runs becomes `current_user` afterward — this is exactly the fixation primitive.

Attack flow:
1. Attacker obtains or sets a known session id in the victim's browser for the Shipit host (e.g., via a subdomain cookie-setting bug, a response-splitting bug, or simply pre-seeding a cookie for a host that doesn't yet have `Secure`/session-scoping issues — this precondition is about the victim's browser holding *a* session cookie the attacker also knows, not about defeating cookie security itself).
2. Attacker sends the victim a link to `GET /github/auth/github` (the OmniAuth entry point) with no `origin` param.
3. Victim, using the browser session the attacker already knows, completes the real GitHub OAuth handshake with their own GitHub account.
4. `callback` fires: `session[:user_id]` and `session[:authenticated]` are written onto the *existing* (attacker-known) session id — no rotation occurs.
5. Attacker, holding the same session id/cookie, now has a fully authenticated session as the victim.

No existing guard prevents this: `verify_signature`/webhook checks are unrelated (this path is browser session, not webhook HMAC); `ExplicitParameters` schemas don't apply to this controller; `force_github_authentication` only fires on *subsequent* requests and only resets session for *already logged-in, stale* users, not for the fixation window during initial login; OmniAuth's CSRF `state` param (if configured) protects the OAuth handshake integrity itself but does not protect the Rails session identifier from fixation, since the vulnerability is server-side (Shipit's own `callback` never rotating the cookie), independent of whether the OAuth exchange itself was legitimate.

### Impact Explanation
An attacker who can get a victim to click a link and later log in via GitHub can hijack the resulting authenticated Shipit session, gaining `current_user`'s privileges — including any deploy/rollback/merge actions the victim's Shipit account is authorized for. This matches the High category explicitly listed in scope: "session fixation / forced OAuth completion." It is repeatable per victim and not limited to a single repository/stack; the blast radius is bounded by whatever the fixated victim account is authorized to do in Shipit (per `Shipit.github_teams` membership).

### Likelihood Explanation
The main precondition — getting the attacker's chosen session id into the victim's browser before login — is the classical session-fixation precondition and is generally the hard part of this class of exploit in modern Rails apps that use signed, `HttpOnly` cookie-store sessions (which resist trivial injection via XSS-free vectors). However, the specific bug being flagged here is squarely in this engine's code: regardless of how the attacker fixates the id, Rails' documented mitigation is exactly `reset_session` on login, and this engine implements it everywhere else (`logout`, forced re-login) but omits it on the actual login success path in `callback`. That omission is a concrete, demonstrable defect independent of the exact fixation delivery mechanism.

### Recommendation
Call `reset_session` at the start of `callback`, before writing any session keys, e.g.:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?

  reset_session
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
```

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback rotates the session id on login" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(
      raw_info: OmniAuth::AuthHash.new(
        id: 44, name: 'Shipit User', email: 'shipit-user@example.com',
        login: 'shipit-user', avatar_url: 'https://example.com',
        api_url: 'https://github.com/api/v3/users/shipit-user'
      )
    )
  )
  @request.env['omniauth.auth'] = auth

  # simulate attacker-seeded session id existing before login
  get :callback
  session_id_before = @request.session.id

  @request.session.delete(:user_id)
  @request.session.delete(:authenticated)
  @request.env['omniauth.auth'] = auth

  get :callback
  session_id_after = @request.session.id

  refute_equal session_id_before, session_id_after,
    "Expected session id to be rotated (reset_session) on successful login to prevent fixation"
end
```
This test fails on current code because `callback` never calls `reset_session`, so `session.id` before and after authentication remains identical.

### Citations

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-21)
```ruby
    def callback
      return_url = request.env['omniauth.origin'] || root_path
      auth = request.env['omniauth.auth']

      return render('failed', layout: false) if auth.blank?

      session[:user_id] = sign_in_github(auth)

      # We need to set this so that the /events and /sidekiq endpoint
      # which leverage `UserRequiredMiddleware` will recognize the user
      # is authenticated.
      session[:authenticated] = true

      redirect_to(return_url)
    end
```

**File:** app/controllers/shipit/github_authentication_controller.rb (L23-26)
```ruby
    def logout
      reset_session
      redirect_to(root_path)
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-24)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
```

**File:** app/controllers/concerns/shipit/authentication.rb (L36-42)
```ruby
    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

### Title
Session fixation via `GithubAuthenticationController#callback` not calling `reset_session` before binding `session[:user_id]` - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` assigns `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` directly on the existing session, without ever calling `reset_session`. Rails does not rotate the session id automatically, so any session id an attacker planted in a victim's browser before the OAuth flow remains valid and becomes bound to the victim's GitHub identity as soon as the victim completes login.

### Finding Description
The broken binding: prior to the fix, `session.id after callback == session.id before callback`, while the claimed-safe binding should be `session.id after callback != session.id set by any party other than the authenticated user`. Concretely: [1](#0-0) 

`callback` reads `request.env['omniauth.auth']`, derives/creates a `User` via `sign_in_github`, and writes `session[:user_id]` and `session[:authenticated]` into whatever session the request currently carries — it never calls `reset_session`. Compare with `logout`, which does call `reset_session`, showing the omission in `callback` is not general policy but a specific gap: [2](#0-1) 

Downstream, `current_user`/`find_current_user` in the `Authentication` concern trust `session[:user_id]` unconditionally to look up the `User`: [3](#0-2) 

Exploit flow: the attacker gets a known session cookie into the victim's browser (e.g., a cross-subdomain cookie write, or by getting the victim to click a link to the app that establishes a session before authentication) and then lures the victim into completing the GitHub OAuth flow (`/github/auth/github` → GitHub → `/github/auth/github/callback`). Because `callback` never rotates the session id, the attacker's pre-known session cookie continues to be valid after `session[:user_id]` is set to the victim's user id. The attacker can then present that same cookie to the app and be treated as the victim by `current_user`, gaining whatever access the victim has (stack access, deploys, etc., depending on `current_user.authorized?` and `Shipit.github_teams` membership of the victim).

No existing guard mitigates this: `force_github_authentication` only checks `current_user.logged_in?`/`authorized?`/`requires_fresh_login?`, none of which detect or prevent session fixation; `GithubAuthenticationController` does not even include the `Authentication` concern, so no additional protection runs on `callback`.

### Impact Explanation
This is a session fixation / authentication bypass: the attacker ends up controlling a session id that is subsequently authenticated as the victim, letting the attacker act as the victim against the Shipit instance (view/trigger deploys, rollbacks, etc., depending on the victim's `Shipit.github_teams` membership and stack permissions). This matches the "High: session fixation / forced OAuth completion" impact category. It is repeatable against any victim the attacker can get to authenticate while carrying the attacker's session id.

### Likelihood Explanation
Requires: (1) Shipit deployed with cookie-based sessions (the Rails default `ActionDispatch::Session::CookieStore` unless overridden by the host app), (2) an ability to fix a session id in the victim's browser prior to OAuth completion — e.g., via a subdomain cookie-scoping issue, a captured pre-auth session cookie link, or any mechanism common to classic session-fixation attacks — and (3) social engineering the victim into completing GitHub OAuth against the app while that session cookie is active. This is a known class of attack (OWASP session fixation) and the attacker needs no Shipit credentials, secrets, or privileged role — only the ability to influence the victim's session cookie and get them to log in.

### Recommendation
Call `reset_session` at the start of `callback` (or immediately after obtaining `auth`, before assigning `session[:user_id]`) so a fresh session id is issued to the newly authenticated user, e.g.:
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
Minitest plan (`test/controllers/github_authentication_controller_test.rb` pattern, not to be placed under out-of-scope dirs but illustrative):
```ruby
test "callback does not fixate session id" do
  # Simulate attacker pre-seeding a session id
  attacker_session_id = session[:_csrf_token] # or manually set via `session.id =`
  get :callback # before login, capture cookies.signed[:_session_id] value: pre_id

  user = shipit_users(:walrus)
  mock_auth = OmniAuth::AuthHash.new(
    provider: 'github',
    extra: { raw_info: { id: user.github_id, login: user.login } },
    credentials: { token: 'abc' }
  )
  request.env['omniauth.auth'] = mock_auth

  post :callback

  post_id = cookies.signed[:_session_id] # or `session.id`
  assert_not_equal pre_id, post_id, "session id must be rotated after authentication to prevent fixation"
  assert_equal user.id, session[:user_id]
end
```
Assertion pair: `session.id_before == session.id_after` should be **false** after the fix (currently true), while `session[:user_id] == user.id` remains true in both cases — demonstrating the same session id an attacker could have planted becomes authenticated as the victim under the current code.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L36-42)
```ruby
    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

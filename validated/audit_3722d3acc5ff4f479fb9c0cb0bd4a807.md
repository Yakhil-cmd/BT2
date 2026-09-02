Confirmed: `GithubAuthenticationController#callback` does not call `reset_session` before or after assigning `session[:user_id]`, unlike `#logout` which does call `reset_session`. [1](#0-0) [2](#0-1) 

### Title
Session fixation via `GithubAuthenticationController#callback` not calling `reset_session` before binding `session[:user_id]` - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`callback` writes `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` directly into whatever session already exists for the request, without ever calling `reset_session`. Since Rails preserves the session id across this write, an attacker who can fix a victim's session id before the victim completes GitHub OAuth ends up with a session id that is now authenticated as the victim.

### Finding Description
The broken binding: the session id used by `callback` after OAuth completes should satisfy `session.id (after callback) != session.id (before callback / attacker-supplied)`, i.e., the session identifier must be rotated on privilege change. Instead, in `app/controllers/shipit/github_authentication_controller.rb` lines 7-21, `callback` only calls `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true`, never `reset_session`. By contrast `logout` (lines 23-26) explicitly calls `reset_session`, showing session rotation is a known concern elsewhere in the same controller but omitted from the far more security-sensitive `callback` action.

Downstream, `current_user`/`find_current_user` in `app/controllers/concerns/shipit/authentication.rb` (lines 36-42) trust `session[:user_id]` unconditionally to resolve the authenticated `User`. There is no secondary binding (e.g., to a rotated CSRF token, device fingerprint, or IP) that would invalidate a session id whose identity changed underneath it.

Exploit flow: an attacker who can cause the victim's browser to carry a session cookie with an attacker-known value (e.g. by writing a cookie for the domain or a shared parent domain, or by getting the victim to click a link that establishes a session before authentication — Rails' default cookie store will keep an id absent an explicit `reset_session`) waits for the victim to log in via `/github/auth/github` -> `/github/auth/github/callback`. After the victim completes the OAuth handshake, the attacker's known session id now has `session[:user_id]` set to the victim's `User#id` and `session[:authenticated] = true`, and the attacker can use that same cookie to act as the victim.

No existing guard prevents this: `force_github_authentication` only checks whether a user is currently logged in and authorized, it does not verify session freshness at login time (`app/controllers/concerns/shipit/authentication.rb` lines 20-34). OmniAuth's `state` parameter protects against CSRF-forced OAuth completion targeting the wrong provider account, not against reuse of a fixed local session id after a legitimate OAuth exchange.

### Impact Explanation
Successful exploitation lets the attacker impersonate the victim in Shipit: read stack state, trigger deploys/rollbacks, and act with the victim's permissions/team membership once the fixed session becomes authenticated. This is a session-fixation authentication bypass, matching the "High" impact category (session fixation / forced OAuth completion) called out in the rules. It's repeatable against any victim the attacker can get to complete OAuth on a session id the attacker controls, and blast radius scales with the victim's actual Shipit privileges (which could include stack-admin/deploy rights).

### Likelihood Explanation
Preconditions: the attacker must be able to fix a session id in the victim's browser before the OAuth login (e.g., via a subdomain able to set a cookie for the shared parent domain, or a scenario where the app doesn't mark/rotate session cookies as `httponly`/`secure` combined with cross-subdomain cookie scoping — a common real-world setup for internal tools on shared domains). No Shipit secrets, tokens, or privileged roles are required, satisfying the "unprivileged attacker" constraint. This is a standard, well-understood web attack class (OWASP session fixation) and requires no interaction with GitHub's API or secrets — only control over the victim's session cookie before login and getting the victim to authenticate normally.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before assigning `session[:user_id]`/`session[:authenticated]`, exactly as already done in `#logout`, so a new session id is issued upon every successful authentication.

### Proof of Concept
Minitest (`ActionController::TestCase` style, matching existing `test/controllers/github_authentication_controller_test.rb`):
```ruby
test ":callback rotates the session id to prevent fixation" do
  # Simulate attacker fixing a session id/value before victim logs in.
  session[:preexisting] = 'attacker-planted-marker'
  fixed_session_id = @request.session.id # capture pre-auth session identity

  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Victim', email: 'victim@example.com',
      login: 'victim', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/victim'
    ))
  )
  @request.env['omniauth.auth'] = auth

  get :callback

  # Assert binding is broken: attacker's pre-existing session identity
  # is the same object that is now bound to the victim's user id.
  assert_equal fixed_session_id, @request.session.id,
    "Expected session id to be rotated on login, but it was preserved (fixation)"
  assert session[:user_id].present?
  assert_equal User.find_by(login: 'victim').id, session[:user_id]
end
```
Expected result on the current code: the assertion `assert_equal fixed_session_id, @request.session.id` passes (proving the id was *not* rotated) while `session[:user_id]` is now the victim's id — demonstrating the fixation. After adding `reset_session` to `callback`, this test should be updated to assert the session id changes (`refute_equal`), confirming the fix.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L36-42)
```ruby
    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

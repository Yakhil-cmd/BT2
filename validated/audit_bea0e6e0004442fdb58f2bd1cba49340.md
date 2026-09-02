Confirmed: `GithubAuthenticationController#callback` never calls `reset_session` before assigning `session[:user_id]` and `session[:authenticated] = true`, while `logout` and the stale-login branch of `force_github_authentication` both correctly call `reset_session`. [1](#0-0) [2](#0-1) 

### Title
Session fixation on GitHub OAuth callback due to missing `reset_session` - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` writes `session[:user_id]` and `session[:authenticated] = true` directly onto the pre-existing session without calling `reset_session`, unlike `logout` and the stale-login path of `force_github_authentication` which both regenerate the session. This lets a session issued to an anonymous visitor be promoted in place to an authenticated session, violating the classic session-fixation defense.

### Finding Description
The broken binding: `session.id` (or the session cookie value) issued to the visitor *before* OAuth == `session.id` trusted *after* `session[:authenticated] = true` is set.

Path: any visitor hitting the Shipit host is issued a session (Rails lazily generates one on first access, e.g. via `force_github_authentication` reading `current_user`/`session[:user_id]` at [3](#0-2) ). That pre-login session is unauthenticated (`session[:authenticated]` unset). When the victim later completes GitHub OAuth, `callback` does:
```ruby
session[:user_id] = sign_in_github(auth)
session[:authenticated] = true
```
with no `reset_session` call in between [4](#0-3) . The same underlying session identity that existed pre-login continues to be valid and is now upgraded to an authenticated one.

By contrast, the engine's own code demonstrates awareness of this requirement: both `logout` [5](#0-4)  and the "stale login" branch of `force_github_authentication` [2](#0-1)  call `reset_session` before redirecting to re-authenticate — but the actual login/upgrade path (`callback`) omits it. None of the other guards (`force_github_authentication`, `User#authorized?`, CSRF protection) address this because they only gate access based on session content, not session identity continuity across the trust-level transition.

### Impact Explanation
If an attacker can cause a victim's browser to carry a session cookie/identifier known to (or controlled by) the attacker prior to login — e.g., via cookie tossing on a shared parent domain, response header injection, or any mechanism that sets a cookie for the Shipit host on the victim's browser — then once the victim completes GitHub OAuth through that session, the attacker's copy of the same session becomes authenticated as the victim. The attacker then inherits the victim's `current_user` identity and can perform any action the victim can perform, including triggering deploys/rollbacks (`POST /stacks/.../deploys`) — an unauthorized deploy performed under the victim's identity. This matches the "session fixation / forced OAuth completion" High-impact category called out in scope.

### Likelihood Explanation
Exploitation requires the attacker to have some means of planting a specific session cookie value on the victim's browser before the victim logs in (the classic session-fixation precondition — e.g., cookie tossing, non-HttpOnly cookie plus a client-side write vector, or a shared-domain quirk). This engine does not itself provide a mechanism to set the victim's cookie remotely (no exploitable step is present in this engine's code for delivering the fixed session id itself), so real-world exploitability depends on external delivery of the fixation, but the root-cause defect — failing to regenerate the session at the authentication boundary — is squarely a defect in this engine's `callback` action, and is trivially detectable/reproducible without any secrets.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before setting `session[:user_id]` and `session[:authenticated]`, e.g.:
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
Minitest (ActionDispatch::IntegrationTest) plan under `test/controllers/`:
1. `get '/'` (or any Shipit-mounted path) as an anonymous client to force session creation; capture the `Set-Cookie` header / `session[:session_id]` value, call it `pre_id`.
2. Stub `request.env['omniauth.auth']` (via `OmniAuth.config.test_mode = true` and `OmniAuth.config.mock_auth[:github]`) and issue `get '/github/auth/github/callback'` reusing the same cookie jar.
3. After the callback, read the session again (e.g. via a test-only route or by inspecting `session[:session_id]`), call it `post_id`.
4. Assert `pre_id == post_id` (fails today after fix — asserting inequality is the correct post-fix expectation; pre-fix it demonstrates the equality that constitutes the vulnerability).
5. With the same original cookie jar (representing the attacker's earlier-acquired session), issue `POST /stacks/:owner/:repo/:env/deploys` and assert it succeeds/redirects as an authenticated user, proving the attacker-known pre-login session became a valid authenticated session without any `reset_session` boundary.

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

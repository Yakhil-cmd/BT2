### Title
Session fixation on GitHub OAuth login — no session rotation on authentication ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` writes the authenticated user's identity directly into the existing session (`session[:user_id]`, `session[:authenticated]`) without first calling `reset_session`. This breaks the binding that should hold between "the session identifier a browser holds before authentication" and "the session identifier that is authorized to represent a specific `User` after authentication" — the same session id persists across the trust boundary, exactly the class of GitHub-identity-vs-session-`User` mismatch called out as in-scope. [1](#0-0) 

### Finding Description
The OAuth callback action performs:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [1](#0-0) 

No `reset_session` (or equivalent session-id rotation) is invoked before the privileged `user_id`/`authenticated` keys are written. Compare this to the `logout` action, which explicitly calls `reset_session` when tearing a session down: [2](#0-1) , and to `Authentication#force_github_authentication`, which only calls `reset_session` in the unrelated "stale token" branch, not on a fresh, successful login: [3](#0-2) .

Session state (`current_user`) is derived purely from `session[:user_id]`: [4](#0-3) . Because the Rails cookie-store session id is not rotated on login, any session cookie value that existed in the browser prior to the OAuth handshake continues to be valid and simply gets upgraded in place to point at the authenticated `User` once the victim completes the GitHub OAuth flow.

Binding broken (before vs. after the OAuth callback):
- Before: `session_id == S` (attacker-issued/known, unauthenticated) 
- After: `session_id == S` still, but now `session[:user_id] == victim.id` (authenticated)

The equality that should be enforced — `session_id_before_auth != session_id_after_auth` — does not hold in this code path.

### Impact Explanation
If an attacker can get a victim's browser to carry a session cookie value known to the attacker before the victim completes GitHub sign-in (e.g., by getting the victim to visit the Shipit host and picking up the cookie, or via a subdomain/cookie-tossing setup, or shared/non-HttpOnly cookie manipulation), the attacker's held copy of that same session id becomes authenticated as the victim the moment the victim finishes the OAuth flow, since `callback` never rotates the session id. This grants the attacker the victim's authenticated session, including whatever `Shipit.github_teams` authorization and stack-level UI access that user has — i.e., escalation into `Shipit.github_teams` authorization, listed explicitly as a qualifying High-impact outcome.

### Likelihood Explanation
Exploitability depends on the attacker's ability to fixate a session id in the victim's browser before login, which is feasible in common configurations (e.g., the app doesn't set the session cookie only after login, cookies not scoped tightly, or an attacker-supplied session cookie is accepted pre-auth as shown by `find_current_user` unconditionally trusting whatever `session[:user_id]` is present at request time). This is a well-known, low-complexity web application weakness class (session fixation), and no privileged credential, API token, or GitHub App secret is required by the attacker — only web access to get a victim onto a chosen session id and to wait for them to log in.

### Recommendation
Call `reset_session` (or otherwise force a new session id, e.g., via `request.session_options[:id] = nil` before assignment) at the start of `GithubAuthenticationController#callback`, prior to setting `session[:user_id]` and `session[:authenticated]`, so a fresh session id is always issued upon successful authentication, mirroring the rotation already done for stale-token logout/re-login paths.

### Proof of Concept
1. Attacker visits the Shipit host (or otherwise causes the victim's browser to carry a session cookie value `S` that the attacker also possesses/controls, unauthenticated: `session[:user_id]` is empty).
2. Attacker lures the victim (who has legitimate GitHub org membership) into visiting a Shipit login link while the browser still holds cookie `S`.
3. Victim completes the GitHub OAuth handshake; `GithubAuthenticationController#callback` fires and executes `session[:user_id] = sign_in_github(auth)` without rotating the session id, per [5](#0-4) .
4. The underlying Rails session identified by cookie `S` is now authenticated as the victim `User`.
5. The attacker, still holding cookie `S`, sends requests to the Shipit UI; `Authentication#find_current_user` resolves `current_user` from `session[:user_id]` and grants the attacker the victim's authenticated privileges, including any `Shipit.github_teams` gated stack access, per [4](#0-3) .

Note: I was unable to directly inspect the session-cookie issuance configuration (`config/initializers/session_store.rb` in a production app, cookie `secure`/`HttpOnly`/domain scoping) inside this engine's own code, since the actual session store setup lives in the host application rather than in `app/**`/`lib/shipit/**` of this engine; that piece of the exploit precondition (how the attacker fixes a known session id into the victim's browser) is host-app-dependent and outside what I could verify from the engine code alone.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
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

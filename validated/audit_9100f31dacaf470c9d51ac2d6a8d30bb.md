### Title
Session fixation on GitHub OAuth callback due to missing session ID rotation - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
The analog bug class from the report is a mismatched-field check that breaks a trust binding (the code checks/derives one thing but the security-relevant effect is applied to a different, unguarded thing). In `shipit-engine`, the equivalent binding that should hold is: `session identifier before authentication == session identifier after authentication` must NOT hold — the session ID must be rotated when a user transitions from anonymous to authenticated. `GithubAuthenticationController#callback` binds the authenticated GitHub identity to the *existing* session without first invalidating/regenerating it, unlike the other two session-transition paths in the engine (`logout` and the "requires fresh login" branch), which both explicitly call `reset_session`.

### Finding Description
The OAuth callback assigns identity into whatever session already exists on the request, rather than issuing a fresh session: [1](#0-0) 

Compare this to the other two places in the engine that transition session authentication state, both of which correctly call `reset_session` before/at the transition: [2](#0-1) [3](#0-2) 

`callback` writes `session[:user_id]` and `session[:authenticated]` directly into `session`, which is backed by the cookie store configured in the host app (e.g. `Rails.application.config.session_store :cookie_store`), and this is the same mechanism `find_current_user` trusts to bind a request to a `User`: [4](#0-3) 

Because the session ID (cookie value) is never rotated at the moment of privilege elevation (anonymous → authenticated), an attacker who can get a victim's browser to carry an attacker-known/attacker-chosen session cookie prior to the OAuth flow will have that same session become fully authenticated as the victim's `User` once the victim completes GitHub OAuth — breaking the intended binding of `GitHub identity` to a `session` that only the authenticating browser should control.

### Impact Explanation
This matches the explicitly listed High-impact category "session fixation / forced OAuth completion" — an attacker who fixates a session ID and then lures/forces the victim through the GitHub OAuth flow ends up holding a valid, fully-authenticated session for the victim's `Shipit::User`, without ever knowing the victim's GitHub credentials. From there the attacker inherits the victim's authorization (`current_user.authorized?`, team membership, `github_access_token`) for as long as the session remains valid, enabling unauthorized actions (deploys, rollbacks, etc.) gated purely on session-bound `current_user`.

### Likelihood Explanation
Exploitation requires an attacker-controlled cookie value to be present in the victim's browser before OAuth completion (e.g., via a subdomain cookie-writing weakness, session ID embedded/leaked in a shared/log-exposed context, or a misconfigured cookie scope in the hosting app). This is a real but conditional prerequisite, which is why the standard mitigation (`reset_session` on login) exists — its absence here is the concrete, code-level defect, consistent with the analog bug class (state trusted post-hoc without re-validating/rotating the binding at the moment of privilege change).

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before assigning `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and in `force_github_authentication`'s fresh-login branch:

```diff
 def callback
   return_url = request.env['omniauth.origin'] || root_path
   auth = request.env['omniauth.auth']

   return render('failed', layout: false) if auth.blank?

+  reset_session
   session[:user_id] = sign_in_github(auth)
   session[:authenticated] = true

   redirect_to(return_url)
 end
```

### Proof of Concept
1. Attacker obtains/sets a known session cookie value in the victim's browser prior to authentication (e.g., via a cookie-scope weakness in the deployment, or by having the victim visit an attacker-supplied link before initiating login, depending on host-app cookie configuration).
2. Victim proceeds through `/github/auth/github` → GitHub OAuth consent → `GithubAuthenticationController#callback`.
3. `callback` sets `session[:user_id] = sign_in_github(auth)` on the *pre-existing* session without rotating it — the session cookie value the attacker fixated is now bound to the victim's authenticated `User` record.
4. Attacker reuses that same (already-known) session cookie to access Shipit as the victim, per `find_current_user` in `app/controllers/concerns/shipit/authentication.rb:36-42`.

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

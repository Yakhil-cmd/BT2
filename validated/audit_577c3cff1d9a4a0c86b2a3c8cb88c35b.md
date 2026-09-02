### Title
Session fixation via GitHub OAuth callback — GitHub identity authenticated is bound to a pre-existing, attacker-controllable session — ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` writes `session[:user_id]` and `session[:authenticated]` into whatever session already exists for the current request, without ever rotating/regenerating the session identifier. This breaks the intended binding: `GitHub identity authenticated` == `User bound to the session id that the browser will keep using`. An unprivileged attacker who can get a victim to browse the login flow while holding a session id chosen (or already known) by the attacker can end up sharing a post-authentication, fully-authenticated session with the victim.

### Finding Description
`app/controllers/shipit/github_authentication_controller.rb`:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
```
No `reset_session` (or `session.regenerate`/ID rotation) call precedes the assignment of `session[:user_id]`. Compare this to `logout`, in the same controller, which explicitly calls `reset_session`, and to `Shipit::Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb`), which also calls `reset_session` only when a stale token is detected — i.e. the codebase treats `reset_session` as the correct mechanism for invalidating the current session id, but never applies it at the moment authentication actually succeeds.

The authorization model in `app/controllers/concerns/shipit/authentication.rb` trusts `session[:user_id]` completely to resolve `current_user`:
```ruby
def find_current_user
  session[:user_id].present? && User.find_by(id: session[:user_id])
end
```
Because the session cookie's underlying id/value is never rotated on login, whichever cookie/session record was active in the browser before OAuth completed remains active and authenticated afterward. If that session identifier was established or is known by an attacker (e.g., a link that pre-sets a Shipit session cookie, or a shared/reused cookie set before the login), the attacker's own browser session becomes bound to the victim's `session[:user_id]` after the victim finishes the GitHub OAuth handshake in that same session context — or conversely, the attacker's known session id, once authenticated by the victim, gives the attacker access to a fully authenticated Shipit session as that victim, with all of the victim's `Shipit.github_teams` authorization already resolved (`current_user.authorized?`) and all their session-bound privileges (creating deploys, locking stacks, viewing stack/task/deploy output, etc.) usable directly through the browser without ever touching `GITHUB_TOKEN`, `api_clients_secret`, or a private key.

This matches the report's bug class precisely: just as `Vault::takeFees`'s `highWaterMark` binding (share value recorded at the time of a state-changing call) can be overwritten by an unprivileged front-runner before the privileged fee-collection acts on it, here the *authenticated identity* is bound to a session id that was fixed *before* the authentication step ran, so the party who controls that pre-existing session id inherits the post-login trust state — an unprivileged attacker (no `Shipit` credentials of any kind needed) can win the race/binding without ever presenting valid GitHub credentials themselves.

### Impact Explanation
This is a session fixation vulnerability leading to authentication bypass / account takeover of the Shipit session — an unauthenticated attacker can gain a fully authenticated session bound to a victim's identity (or force the victim into an attacker-controlled but now-authenticated session), which the impact rubric explicitly lists as an acceptable High-severity outcome ("session fixation / forced OAuth completion"). Once inside such a session, the attacker inherits the victim's `Shipit.github_teams` authorization (`current_user.authorized?` in `app/controllers/concerns/shipit/authentication.rb`), enabling unauthorized deploys, rollbacks, locks, and reads of stack/task/deploy output — actions normally gated behind GitHub org/team membership.

### Likelihood Explanation
Exploitability depends on how the session cookie is issued/stored (e.g., whether Rails' default `ActionDispatch::Session::CookieStore` is used and whether the session id/value is attacker-settable prior to login, e.g. via subdomain cookie injection, a shared/proxy cache, or a pre-authentication response that already sets a session cookie the attacker can read/predict). Since the login flow itself (`GET /github/auth/github`) is unauthenticated and reachable by anyone, and the callback path unconditionally reuses the existing session without rotation, the only prerequisite is the classic session-fixation setup (attacker gets a victim to use a session id known to the attacker before completing OAuth). No GitHub App credentials, webhook secret, or API client token are required.

### Recommendation
Call `reset_session` (or explicitly rotate the session id, e.g. `request.session_options[:renew] = true` / regenerate the session id) in `GithubAuthenticationController#callback` immediately before setting `session[:user_id]` and `session[:authenticated]`, mirroring the pattern already used in `logout` and in `force_github_authentication`. This ensures a brand-new session identifier is issued at the moment of authentication, severing any binding to a pre-existing (potentially attacker-fixed) session.

### Proof of Concept
1. Attacker visits Shipit and notes/sets a session cookie value `S` (e.g., by simply loading the app, or via any mechanism that lets them fix the cookie value in the victim's browser — subdomain cookie write, response splitting, or shared browser/profile).
2. Attacker sends the victim a link to `/github/auth/github` (the unauthenticated login-start route in `config/routes.rb`) using session `S`, with `origin` pointing wherever.
3. Victim, using session `S`, completes the GitHub OAuth dance; `GithubAuthenticationController#callback` runs:
   ```ruby
   session[:user_id] = sign_in_github(auth)
   session[:authenticated] = true
   ```
   No session id rotation occurs, so session `S` is now a valid, fully authenticated session bound to the victim's `User` record.
4. Attacker reuses session `S` (already known/fixed by them in step 1) to access Shipit as the victim — reading stack/deploy/task data and triggering privileged actions gated only by `current_user.authorized?` (`app/controllers/concerns/shipit/authentication.rb`). [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

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

**File:** app/controllers/concerns/shipit/authentication.rb (L18-34)
```ruby
    private

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

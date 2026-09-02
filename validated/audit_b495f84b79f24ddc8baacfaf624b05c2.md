[1](#0-0) [2](#0-1) 

### Title
Session fixation in GitHub OAuth callback — session identity is bound without regenerating the session - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` authenticates a user via OmniAuth/GitHub and writes the resulting identity directly into the existing session (`session[:user_id] = sign_in_github(auth)`) without ever calling `reset_session`. Every other place in the engine that changes authentication state (`logout`, and the stale-login branch of `force_github_authentication`) explicitly calls `reset_session`, but the actual login path — the moment a "GitHub identity" is bound to a `Shipit::User` and to the browser's session — does not.

### Finding Description
The engine's authentication concern treats `session[:user_id]` as the sole binding between a request and a `User`: [3](#0-2) 

`force_github_authentication` redirects unauthenticated requests to `github_authentication_path`, and on stale logins it calls `reset_session` before re-redirecting: [4](#0-3) 

But the OAuth callback that actually performs the login never regenerates the session before storing the freshly-authenticated identity: [1](#0-0) 

Only `logout` resets the session: [5](#0-4) 

This breaks the intended binding "GitHub identity == the `User` bound to *this* session": the session identifier (and any state within it) that existed *before* the victim completed GitHub OAuth is the same one that becomes authenticated *after* completion, because the session is never rotated at the login boundary. If an attacker can get a victim's browser to carry a session token of the attacker's choosing prior to the OAuth callback firing (a classic session-fixation setup — e.g. via a subdomain-scoped cookie, a shared/public terminal, or any mechanism that lets the attacker plant a session cookie value before the victim clicks "Login with GitHub" and completes the flow), the attacker's pre-known session subsequently becomes bound to the victim's authenticated `User` record, since `sign_in_github` writes into the existing session rather than a freshly rotated one.

### Impact Explanation
If exploitable session-fixation is possible against the host application's chosen session store, the attacker ends up controlling a fully authenticated session for the victim's `User`, which under `Shipit::Authentication` grants access to all actions gated by `current_user`/`current_user.authorized?`, i.e., an unauthenticated attacker escalates into an authenticated Shipit user's privileges — this matches the "session fixation / forced OAuth completion" High-impact category called out in the analog rules.

### Likelihood Explanation
Likelihood is conditioned on the deploying application's session-store configuration (e.g., a server-side session store keyed by a session id cookie) — the engine itself doesn't pin this, and `test/dummy/config/initializers/session_store.rb` exists but its exact contents (cookie-store vs. server-backed store) could not be retrieved from the index in this scan. Regardless of store, the missing `reset_session` at the login boundary is a concrete, unconditional deviation from the pattern the codebase itself follows elsewhere (`logout`, stale-login handling), and is the root cause that would need to be present for any session-fixation attack chain to succeed here.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` immediately before (or as part of) setting `session[:user_id]`/`session[:authenticated]`, so a freshly authenticated GitHub identity is always bound to a newly generated session rather than any session that existed prior to the OAuth handshake.

### Proof of Concept
1. Attacker obtains/sets a session cookie value (session fixation vector dependent on host deployment configuration, e.g., a shared subdomain or a session store that accepts attacker-supplied ids) and gets it planted in the victim's browser before authentication.
2. Victim visits Shipit, is redirected by `force_github_authentication` to `/github/auth/github`, completes GitHub OAuth.
3. `GithubAuthenticationController#callback` runs `session[:user_id] = sign_in_github(auth)` on the *existing* (attacker-known) session rather than a freshly rotated one [6](#0-5) .
4. Attacker, already holding the same session identifier, is now recognized by `find_current_user` as the victim's `User` [7](#0-6) .

Note: full exploitability depends on the session-store mechanics configured by the host Rails application (outside this engine's own code, per scope), which I could not fully confirm from the indexed contents of `test/dummy/config/initializers/session_store.rb`.

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

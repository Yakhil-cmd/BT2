### Title
Session fixation on GitHub OAuth callback — session is not rotated before binding the authenticated GitHub identity - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
This is a structural analog of the reported bug class: a value that is authenticated/verified (here, the GitHub identity returned by OmniAuth) is bound onto a container (the session) that was never re-validated for the same principal, exactly as the fee-market decorator refunded to `FeePayer()` instead of validating who actually authorized/paid. In Shipit, `GithubAuthenticationController#callback` binds the freshly-verified GitHub identity into whatever session already exists (`session[:user_id] = sign_in_github(auth)`), without ever calling `reset_session` on a successful login. The equality that should hold — "the session that ends up authenticated == the session created for this specific GitHub login" — is not enforced.

### Finding Description
`GithubAuthenticationController#callback` performs the OmniAuth login and stores the resulting user id directly into the current session, and separately marks it authenticated: [1](#0-0) 

`sign_in_github` only creates/updates the `User` record and returns its id — it performs no session lifecycle management: [2](#0-1) 

The only place in the engine that ever calls `reset_session` is `Authentication#force_github_authentication`, and only in the narrow case where an *already logged in* user's token format is stale (`requires_fresh_login?`); it is not invoked on a normal, successful new login: [3](#0-2) 

Because `session[:user_id]` is written into the pre-existing session object rather than a freshly rotated one, any session container that was established *before* the GitHub OAuth handshake completes (e.g. a session cookie value known to or fixed by an attacker) becomes authenticated as whichever `User` the victim logs in as. This breaks the required binding: "GitHub identity verified by OmniAuth" vs. "the `User` actually bound to *this* session" — the session's identity is not freshly minted at the authentication boundary, so a pre-authentication session can be silently upgraded to a post-authentication, authorized session for a different (victim) principal.

### Impact Explanation
If an attacker can get a victim's browser to carry a session container established/known to the attacker (session fixation primitive, independent of this engine and dependent on the host's session store/cookie handling), then after the victim completes the real GitHub OAuth flow, the attacker's known session becomes bound to the victim's `User` and `Shipit.github_teams` authorization, because `force_github_authentication`/`current_user` simply reads `session[:user_id]` with no re-validation of session freshness: [4](#0-3) 

This grants the attacker the victim's authenticated web session (stack view/deploy/rollback/task-trigger permissions, team-authorization state), i.e., unauthorized access equivalent to an authentication bypass and escalation into `Shipit.github_teams` authorization — matching the High/Critical impact categories for "session fixation / forced OAuth completion" and "escalation into `Shipit.github_teams` authorization."

### Likelihood Explanation
Exploitability is bounded by how the host application configures its Rails session store; if it uses a purely client-side `CookieStore` (Rails default), classic fixation is largely mitigated because there is no server-side session identifier to fix — the whole state lives in a signed/encrypted cookie the attacker cannot forge without `secret_key_base`. However, the engine itself provides no defense-in-depth (`reset_session`) at the authentication boundary, so any deployment using a server-side session store (`:cache_store`, `ActiveRecord::SessionStore`, Redis-backed sessions, etc. — all supported by Rails and not precluded by this engine) is directly vulnerable via standard cookie-tossing/fixation techniques. Because the vulnerable code path is entirely within the engine's own controller (`GithubAuthenticationController#callback`) and concern (`Authentication#force_github_authentication`), and requires no privileged credential, API token, or webhook secret to exploit — only a pre-established session — this is a legitimate, engine-owned gap in the login flow.

### Recommendation
Call `reset_session` immediately before establishing the authenticated state in `GithubAuthenticationController#callback`, so every successful login always mints a brand-new session container bound to the freshly verified identity:
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
1. Host app configures a server-side session store (e.g. `config.session_store :cache_store` or `:active_record_store`), which is standard, supported Rails configuration and not disallowed by the engine.
2. Attacker obtains/sets a session identifier value that will later be used by the victim's browser (classic fixation delivery — e.g., via a subdomain that can set a cookie for the parent domain, or any mechanism that plants a known session id in the victim's browser before authentication).
3. Victim visits Shipit and completes the real GitHub OAuth handshake; `GithubAuthenticationController#callback` executes: [1](#0-0) 
   Since `reset_session` is never called, the pre-existing (attacker-known) session id now has `session[:user_id]` set to the victim's `User#id` and `session[:authenticated] = true`.
4. Attacker reuses the known session id and is now treated as the victim by `current_user`/`force_github_authentication`: [5](#0-4) 
   gaining the victim's authorization (`Shipit.github_teams` membership check passes, since it operates on the hijacked `current_user`).

Note: I could not fully verify how the *default* dummy/test session store is configured for this engine in downstream deployments beyond `test/dummy` (excluded from scope), so the concrete exploitability depends on host session-store choice; this is called out above as the likelihood caveat.

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-42)
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

    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

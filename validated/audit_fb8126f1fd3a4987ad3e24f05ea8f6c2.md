## Analysis



### Title
Session fixation on GitHub OAuth callback — verified GitHub identity is bound to a pre-existing, attacker-controlled session ID - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` authenticates the GitHub identity via OmniAuth and then writes `session[:user_id]` into whatever session currently exists for the browser, without ever rotating the session identifier. This breaks the equality that should hold between "the GitHub identity that just completed OAuth" and "the session/cookie that ends up bound to the resulting `User`" — an attacker who fixates a session ID in a victim's browser before the victim logs in inherits the victim's authenticated session once OAuth succeeds.

### Finding Description
`Authentication#force_github_authentication` redirects any unauthenticated visitor to `github_authentication_path`, which starts the OmniAuth GitHub flow [1](#0-0) . When OmniAuth completes, `GithubAuthenticationController#callback` runs:

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [2](#0-1) 

`sign_in_github` correctly verifies/creates the `User` from GitHub's `auth.extra.raw_info` and stores the fresh `github_access_token` [3](#0-2) . However, the resulting `session[:user_id]` is written into the *existing* Rack session for the current request — there is no `reset_session` call anywhere in this action, and the only place `reset_session` is invoked in the authentication flow is for a *different* condition (`requires_fresh_login?`, used to force re-login on stale credentials) [4](#0-3) .

`current_user` elsewhere is derived purely from `session[:user_id]`: `session[:user_id].present? && User.find_by(id: session[:user_id])` [5](#0-4) . Nothing rebinds the session cookie's identifier to the newly authenticated identity — the `User` record is bound to whatever session ID the browser presented when hitting `/github/auth/github/callback`.

**The broken equality:** `GitHubIdentity_that_completed_OAuth == User_bound_to_the_resulting_session_cookie`. In a correctly implemented flow the session id itself must be regenerated at the authentication boundary so that a pre-authentication session id can never carry post-authentication privileges. Here that regeneration never happens.

### Impact Explanation
This is a classic session-fixation vulnerability. An attacker who can get a target's browser to adopt a session ID chosen or known by the attacker (e.g., via a subdomain cookie-setting mechanism, a response-splitting/redirect quirk, or simply observing that Shipit issues a session cookie on the very first unauthenticated request and can lure the victim to visit the site first) can:

1. Visit Shipit unauthenticated to obtain/plant a session cookie (or otherwise force a specific `_session_id` into the victim's cookie jar).
2. Get the victim to complete `github_authentication` OAuth using that same session id (e.g., by sending them the pre-established session cookie plus a link to `/github/auth/github`).
3. Because `callback` never rotates the session id, the attacker's known session id is now bound to the victim's authenticated `User`, granting the attacker full access to the victim's Shipit account — including whatever `Shipit.github_teams` authorization the victim carries, the ability to trigger deploys/rollbacks the victim is permitted to trigger, and exposure of the victim's `github_access_token`-backed capabilities exercised through the UI.

This matches the rules' High-impact category "session fixation / forced OAuth completion," and can escalate to Critical-adjacent outcomes (unauthorized deploy/rollback) depending on the victim's team membership, since `authorized?` and downstream deploy permissions are all keyed off `current_user`, which is entirely determined by `session[:user_id]` [6](#0-5) .

### Likelihood Explanation
Medium. No privileged credential, `ApiClient` token, webhook secret, or GitHub App private key is required — only the ability to get a chosen/known session id to persist in the victim's browser across the pre-login and post-login requests, and to lure the victim into completing GitHub OAuth (a normal legitimate action for them, since they already trust Shipit). This is a well-understood, commonly-exploited web class, and the code shows no defensive `reset_session`/`session.clear` call anywhere in the successful OAuth callback path, only on the unrelated "stale credentials" branch.

### Recommendation
Call `reset_session` (or otherwise regenerate the session id, e.g., Rails' `request.session.options[:renew] = true` / recreate the session store entry) in `GithubAuthenticationController#callback` immediately before or after establishing `session[:user_id]`, so that no pre-authentication session id can carry post-authentication identity. Also consider setting the `authenticated` flag and `user_id` atomically into a freshly-issued session, and invalidating/rotating any session id supplied prior to OAuth completion.

### Proof of Concept
1. Attacker visits `https://shipit.example.com/` unauthenticated and records the `_session_id` cookie value issued by Rails (or forces a chosen session id if the deployment is vulnerable to fixation via subdomain/cookie injection).
2. Attacker sends the victim a link/cookie that sets that same session id in the victim's browser, then directs them to `GET /github/auth/github` to log in normally.
3. Victim completes the legitimate GitHub OAuth consent flow; `GithubAuthenticationController#callback` fires and executes `session[:user_id] = sign_in_github(auth)` [7](#0-6)  — using the same (attacker-known) session id, since it is never rotated.
4. Attacker now sends requests using the known session id and is treated as the victim by `current_user` [8](#0-7) , inheriting the victim's Shipit privileges (team-based `authorized?`, deploy triggers, etc.).

**Uncertainty note:** I was not able to independently confirm the exact session-store configuration (e.g., cookie store vs. server-side session store, `session_store.rb` settings, `SameSiteCookieMiddleware` behavior) because these files were outside what my searches surfaced; that configuration affects how easily a session id can be fixated in practice (e.g., cookie-store sessions signed by `secret_key_base` are harder to "plant" than server-side session ids, but the fixation weakness — failure to rotate on login — remains present in the code regardless). A full assessment of exploitability would benefit from reviewing `config/initializers/session_store.rb` and `SameSiteCookieMiddleware`, which the index did not surface.

### Citations

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

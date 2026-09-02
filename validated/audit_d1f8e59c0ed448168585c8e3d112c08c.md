### Title
Session fixation on GitHub OAuth callback — GitHub identity is bound to a pre-existing, attacker-controlled session ID ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` writes the freshly authenticated GitHub identity (`session[:user_id]`) into whatever session already exists on the request, without first calling `reset_session`. This breaks the intended binding "GitHub identity that authenticated == `User` bound to the session" — the session container itself is never rotated, so a session ID established before authentication remains valid after authentication and now carries a real, authorized identity.

### Finding Description
The callback action is: [1](#0-0) 

```
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']

  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true

  redirect_to(return_url)
end
```

Contrast this with `logout`, which does explicitly call `reset_session`: [2](#0-1) 

The engine's own authentication concern also demonstrates awareness that session rotation matters — `force_github_authentication` calls `reset_session` when a stale/legacy token is detected before forcing re-login: [3](#0-2) 

But that rotation only happens on the "stale token" path, not on the actual successful sign-in path (`callback`). `find_current_user` trusts `session[:user_id]` completely for every subsequent request: [4](#0-3) 

Because `callback` never rotates the session identifier, any session cookie that existed in the browser *before* the OAuth dance began is reused *after* the dance completes, and that pre-existing session now becomes a valid, authenticated session for whichever GitHub account just finished the OAuth flow.

### Impact Explanation
This is a classic session-fixation vector: if an attacker can get their own known session ID into a victim's browser (e.g., by setting a cookie for the Shipit host on a shared/subdomain-cookie-exploitable environment, or via a scenario where the session cookie is set on a non-`httponly`/shared path before login), and then induces the victim to complete the GitHub OAuth login (a normal, legitimate login on the victim's part, not phished credentials), the attacker's known session ID becomes bound to the victim's authenticated `User`. The attacker can then reuse that same session ID to impersonate the victim inside Shipit — reading and manipulating stacks, triggering deploys/tasks, etc., all attributed to the victim's `User` record. This falls squarely under the listed High-impact category "session fixation / forced OAuth completion," and via `authorized?` / `Shipit.github_teams` checks, effectively grants the attacker the victim's authorization level.

### Likelihood Explanation
Exploitation requires no credential of any kind (no `ApiClient` token, no webhook secret, no GitHub App key) — only the ability to place a known session identifier into the victim's browser and have the victim complete a normal OAuth login while that session is active. This is a common precondition for session-fixation exploits (e.g., cookie injection via network position, subdomain trust, or a crafted link that sets a session before redirecting to the OAuth flow) and is independent of any Shipit deployment misconfiguration — the vulnerable code path (`callback` failing to call `reset_session`) is present regardless of how the engine is mounted.

### Recommendation
Call `reset_session` (or otherwise regenerate the session ID) in `GithubAuthenticationController#callback` immediately before/after determining the authenticated user and setting `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and in `Authentication#force_github_authentication`. Preserve `return_url`/`omniauth.origin` handling by capturing it into a local variable prior to resetting the session, since `reset_session` clears session state.

### Proof of Concept
1. Attacker visits the Shipit host and obtains a fresh, unauthenticated session cookie `S`.
2. Attacker gets `S` set in the victim's browser for the same host (via any mechanism that allows setting a cookie for the target domain/session store prior to login — e.g. a shared network position, a subdomain relationship, or a crafted pre-auth request that the victim is induced to open in a browser where `S` will be written).
3. Victim, using session `S`, initiates and completes the legitimate GitHub OAuth login flow against Shipit's `/github/auth/github/callback`.
4. `GithubAuthenticationController#callback` executes `session[:user_id] = sign_in_github(auth)` without rotating the session — session `S` is now bound to the victim's `User`.
5. Attacker replays session cookie `S` against the Shipit host and is now treated as the authenticated victim by `Authentication#current_user`/`find_current_user`, gaining the victim's stack access, deploy/task-trigger rights, and team-based authorization.

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

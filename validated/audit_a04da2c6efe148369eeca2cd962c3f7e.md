### Title
Session Fixation in OAuth Callback Allows Authentication Bypass - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` writes `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` into the existing session without ever calling `reset_session`, so the session identifier established before authentication is preserved after login. An attacker can pre-establish an anonymous session, fixate it onto a victim, and after the victim completes the real GitHub OAuth flow, reuse the now-authenticated session as the victim.

### Finding Description
The broken binding is: `session.id (before callback)` == `session.id (after callback)` must be **false** to prevent fixation; in this code it remains **true**.

In `app/controllers/shipit/github_authentication_controller.rb`: [1](#0-0) 

`callback` only mutates `session[:user_id]` and `session[:authenticated]`; it never calls `reset_session`. Compare with `logout`, which correctly calls `reset_session`: [2](#0-1) 

`Shipit::Authentication#force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb`) redirects unauthenticated users to `github_authentication_path`, and `current_user`/`find_current_user` trust `session[:user_id]` directly to look up the `User`: [3](#0-2) 

None of these guards regenerate the session id on login — `reset_session` is only invoked in the `requires_fresh_login?` branch and in `logout`, not in `callback`.

Exploit flow: (1) the attacker issues `GET /github/auth/github` (or any request establishing a Rack session) to obtain a session cookie with no `user_id` set; (2) the attacker delivers that cookie to the victim (e.g., via a subdomain under `Shipit.host` that shares the cookie's domain scope, or any mechanism that sets that exact cookie in the victim's browser); (3) the victim, using that fixed cookie, completes the real GitHub OAuth handshake and hits `callback`; (4) `session[:user_id]` is written into the *same* session record the attacker already possesses; (5) the attacker replays the original cookie and is now recognized as the victim by `current_user`, gaining the victim's authorization level (including `current_user.authorized?` team membership) and can call any action the victim can, e.g. `Stack#trigger_deploy`.

Existing guards do not stop this: `force_github_authentication` only checks presence/authorization of `current_user`, not session provenance; there's no CSRF/state validation of the OAuth flow in this controller that would prevent an attacker from independently causing/observing a session id, and no session-id rotation on privilege elevation from anonymous to authenticated.

### Impact Explanation
This is authentication bypass / session fixation: an attacker who fixates a session onto any victim (via a shared-cookie-domain subdomain or other cookie-setting vector) gains full session-level impersonation of that victim once the victim logs in through GitHub OAuth. This lets the attacker act as the victim in Shipit — including triggering deploys/rollbacks on stacks the victim can deploy (`Stack#trigger_deploy`), reading task streams, etc. The attack is repeatable against any victim who can be lured/forced into using the fixated cookie and is not scoped to a single tenant; it depends only on the attacker's ability to plant a cookie value in the victim's browser under the shared cookie domain, which is outside GitHub-secret/API-token requirements.

### Likelihood Explanation
Preconditions: cookie domain scoping such that an attacker-controlled origin (e.g., a subdomain under `Shipit.host`, or any origin able to set a cookie visible to the Shipit app for that path/domain) can write the same session cookie value that will later be sent by the victim's browser to Shipit. This is a common real-world configuration risk (shared-domain cookies, `same_site`/domain settings) and does not require any Shipit or GitHub secret, admin privilege, or team membership — matching the "unprivileged internet attacker" threat model exactly. Attacker cost is low: one request to obtain a session id, plus a cookie-fixation delivery mechanism to the victim.

### Recommendation
Call `reset_session` (or at minimum regenerate the session id, e.g. via `request.session_options[:renew] = true` equivalent) in `GithubAuthenticationController#callback` immediately before writing `session[:user_id]`/`session[:authenticated]`, mirroring what is already done in `logout` and in the `requires_fresh_login?` branch of `force_github_authentication`. Preserve `return_url`/`omniauth.origin` in a local variable before resetting, since `reset_session` clears the session hash.

### Proof of Concept
Minitest (integration test) plan under `test/`:
1. In an `ActionDispatch::IntegrationTest`, issue a request that establishes an anonymous Rack session (e.g., hit any Shipit route that starts a session, or directly call `get shipit.github_authentication_path`) and capture `session_id_before = request.session.id` (no `session[:user_id]` set).
2. Reuse the same cookie jar/session, stub `request.env['omniauth.auth']` via a test double or `OmniAuth.config.test_mode`, and perform `get shipit.callback_path` (or equivalent) with the victim's auth hash.
3. Assert `assert_equal session_id_before, request.session.id` (proving the id is unchanged — demonstrating the vulnerability) and `assert_equal victim_user.id, session[:user_id]`.
4. To demonstrate the fix works, add the same test asserting `refute_equal session_id_before, request.session.id` after `reset_session` is introduced in `callback`. [1](#0-0) [4](#0-3)

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

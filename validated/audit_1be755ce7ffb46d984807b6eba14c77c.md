### Title
Session Fixation via Missing `reset_session` on GitHub OAuth Callback - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
The engine's own OAuth completion handler assigns the authenticated `user_id` into the *existing* session without first rotating/resetting the session, breaking the binding "GitHub identity authenticated == `User` bound to the session." An attacker who fixes a victim's session identifier before the OAuth handshake completes inherits the victim's authenticated session once the victim finishes logging in with their real GitHub identity.

### Finding Description
`GithubAuthenticationController#callback` is the only place in the engine that turns a verified GitHub identity into an authenticated Shipit session: [1](#0-0) 

It writes `session[:user_id]` and `session[:authenticated] = true` directly onto whatever session already exists for the current request — there is no `reset_session` call, unlike `logout`, which does call it: [2](#0-1) 

Downstream, `Shipit::Authentication#find_current_user` trusts `session[:user_id]` unconditionally to resolve the `current_user` for every privileged action (stacks, deploys, api clients, etc.): [3](#0-2) 

Because the session identifier/cookie is never rotated at the moment of privilege elevation (anonymous → authenticated), any attacker who can plant a session onto a victim's browser before the OAuth flow (a classic pre-login session-fixation setup, e.g., via a shared-domain cookie write, a non-`HttpOnly`/scoped cookie, or simply handing the victim a URL/cookie value that survives the redirect chain through `omniauth.origin`) will find that session promoted to a fully authenticated one as soon as the victim finishes the GitHub OAuth dance. The attacker, holding the same session value, is now logged in as the victim — including their GitHub identity binding used for `authorized?` checks and all repository/stack actions gated by `Shipit::Authentication`.

This is the shipit-engine analog of the report's core weakness class: an authentication completion step that does not adequately bind the verified identity to a fresh, attacker-uncontrolled credential (in the OTP report, a guessable/brute-forceable code; here, a non-rotated session key), letting an attacker step into a legitimate session/account without ever presenting their own valid credential.

### Impact Explanation
This maps to the explicitly in-scope High-impact category "session fixation / forced OAuth completion." A successful fixation attack yields full account takeover of the victim's Shipit identity: `current_user` resolves to the victim, `authorized?` evaluates against the victim's team memberships, and the attacker gains the ability to trigger deploys, rollbacks, manage `api_clients`, and read/write everything the victim's `Shipit::Authentication`-gated role can reach — without ever needing the victim's `github_access_token` or GitHub credentials directly.

### Likelihood Explanation
Exploitability depends entirely on the attacker being able to fix a known session value onto the victim's browser prior to OAuth completion, which requires an environment-specific vector (e.g., cross-subdomain cookie writing, session ID acceptance from a URL parameter, or a non-scoped cookie config in the host application). The engine's own code exhibits the missing-reset defect unconditionally, but real-world exploitability is gated by how the host app configures its session store/cookie scope — the engine provides no mitigating `reset_session` regardless.

### Recommendation
Call `reset_session` (or otherwise rotate the session identifier) inside `GithubAuthenticationController#callback` immediately before assigning `session[:user_id]` and `session[:authenticated] = true`, mirroring the existing `logout` action. This ensures no pre-authentication session value can be inherited post-login.

### Proof of Concept
1. Attacker obtains/observes an anonymous session token `S` for the Shipit host (e.g., visits the site, or plants a session cookie value on the victim's browser through a permissive cookie scope).
2. Attacker lures the victim (who already has session `S` active) into visiting `GET /github/auth/github?origin=...`, initiating the real OmniAuth GitHub flow.
3. Victim authenticates with their own legitimate GitHub account; OmniAuth redirects to:
   `GET /github/auth/github/callback` — handled by: [1](#0-0) 
4. Because `reset_session` is never invoked, session `S` is mutated in place: `session[:user_id] = victim.id`, `session[:authenticated] = true`.
5. Attacker, still holding session `S`, now passes `force_github_authentication`'s `current_user.logged_in?` check via `find_current_user`: [4](#0-3) 
   and is fully authenticated as the victim across all `ShipitController`/`Shipit::Authentication`-protected endpoints (stacks, deploys, api_clients, etc.), confirmed by the shared session assertions in [5](#0-4) .

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

**File:** test/controllers/stacks_controller_test.rb (L34-49)
```ruby
    test "GitHub authentication is mandatory" do
      session[:user_id] = nil
      get :index
      assert_redirected_to '/github/auth/github?origin=http%3A%2F%2Ftest.host%2F'
    end

    test "users which require a fresh login are redirected" do
      user = shipit_users(:walrus)
      user.update!(github_access_token: 'some_legacy_value')
      assert_predicate user, :requires_fresh_login?

      get :index

      assert_redirected_to '/github/auth/github?origin=http%3A%2F%2Ftest.host%2F'
      assert_nil session[:user_id]
    end
```

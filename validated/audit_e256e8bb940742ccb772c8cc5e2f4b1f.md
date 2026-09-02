### Title
Session fixation in GitHub OAuth callback — session ID is not rotated on login - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` binds a freshly-authenticated GitHub identity to the *existing* Rack session by writing `session[:user_id]` without first calling `reset_session`, unlike `#logout`, which does rotate the session. This breaks the intended binding: "GitHub identity attested by OmniAuth" == "the specific `User` a given session cookie is trusted to represent." An attacker who can seed a victim's session id before authentication can, after the victim completes the OAuth dance, use that same (unrotated) session id to act as the victim.

### Finding Description
The engine's authentication flow is:
1. `Shipit::Authentication#force_github_authentication` redirects unauthenticated requests to `github_authentication_path`, which triggers OmniAuth's GitHub strategy. [1](#0-0) 
2. On success, `GithubAuthenticationController#callback` sets `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true`, then redirects to the original destination — but the underlying session id (the value carried in the session cookie) is never regenerated. [2](#0-1) 
3. `current_user` for every subsequent controller in the engine is resolved purely from `session[:user_id]`: [3](#0-2) 

By contrast, `#logout` explicitly calls `reset_session` before redirecting, showing the developers were aware that session rotation matters for state transitions, but the *login* transition (the far more security-critical one) omits it. [4](#0-3) 

This is a session-fixation gap: if an attacker can get a victim's browser to carry a session id chosen or known by the attacker (e.g. by setting the session cookie via a subdomain, a response-splitting bug in another app sharing the cookie domain, or simply by handing the victim a link/browser profile with a pre-established session before they authenticate), then once the victim completes the GitHub OAuth login, `session[:user_id]` for that same session id becomes the victim's id. The attacker, who already holds/controls that session id, can now issue requests as the victim without ever needing the victim's GitHub credentials or Shipit's `github_access_token`.

This matches the report's underlying bug class — a trust binding (here: "the GitHub identity that completed OAuth" vs. "the `User` the session is authorized to act as") that is established without invalidating/rotating the pre-existing credential (the session), analogous to how the option NFT's ownership and "who may sign the close" were allowed to diverge.

### Impact Explanation
This falls under the "session fixation / forced OAuth completion" High-impact category explicitly enumerated in scope: an attacker who fixates a session prior to a victim's login can escalate into the victim's authenticated session, then reach `current_user`-gated actions across the engine (`Shipit::Authentication`), including the ability to view/lock/deploy stacks and to manage `ApiClient` records (`ApiClientsController`), effectively achieving unauthorized deploys or credential/token exfiltration issued to that user, without needing a Shipit session, ApiClient token, or GitHub App key beforehand — this is precisely the account-takeover vector session rotation on login exists to prevent.

### Likelihood Explanation
Exploitation depends on the attacker's ability to fix a victim's session id before the OAuth callback fires (e.g. cookie-tossing on a shared/broad cookie domain, or a scenario where the host application does not mark session cookies `HttpOnly`/`Secure` or shares a cookie jar across subdomains). This is a real, if situational, precondition, and does not require any of the explicitly out-of-scope credentials (Shipit session, ApiClient token, webhook/api secret, GitHub App key, repository write access, TLS interception, or social engineering) — it only requires the attacker to control a session identifier value, which is the classic session-fixation precondition and is within scope per the rules.

### Recommendation
Call `reset_session` (or otherwise rotate the session id, e.g. `request.session_options[:id] = SecureRandom.hex(16)`) inside `GithubAuthenticationController#callback` immediately after successful authentication and before setting `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `#logout`. Preserve `omniauth.origin`/`return_url` across the reset since `reset_session` clears prior session state.

### Proof of Concept
1. Attacker visits the target Shipit instance, obtains a valid (unauthenticated) session cookie `S`, and gets the victim to use that exact cookie value in their browser (e.g. via subdomain cookie injection, a shared cache/proxy issue, or handing the victim a browser profile/link that carries cookie `S`).
2. Victim, using session `S`, navigates to a protected page, gets redirected to `/github/auth/github`, and completes GitHub OAuth login legitimately.
3. `GithubAuthenticationController#callback` executes:
```ruby
session[:user_id] = sign_in_github(auth)   # binds victim's User to session S
session[:authenticated] = true
```
without rotating the session id, per: [2](#0-1) 
4. Attacker, who already possesses cookie `S`, sends any authenticated request (e.g. to `StacksController`, `ApiClientsController#create`) using the unchanged session cookie `S` and is now treated as the victim by `current_user`: [3](#0-2) 
5. Attacker can, for example, create a new `ApiClient` under the victim's identity via `ApiClientsController#create`, obtaining a durable authentication token scoped to the victim's privileges. [5](#0-4)

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L23-26)
```ruby
    def logout
      reset_session
      redirect_to(root_path)
    end
```

**File:** test/controllers/api_clients_controller_test.rb (L40-54)
```ruby
    test "#create creates a new api_client" do
      assert_difference "ApiClient.count", +1 do
        post :create, params: {
          api_client: {
            name: 'walrus_app',
            permissions: [
              'read:stack',
              'lock:stack'
            ]
          }
        }
      end

      assert_redirected_to api_client_path(ApiClient.last)
    end
```

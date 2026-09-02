### Title
Session fixation via GitHub OAuth callback that binds a new identity to a pre-existing session without regenerating it - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` completes the OAuth handshake and writes the resulting identity into the *existing* session (`session[:user_id] = sign_in_github(auth)`), but never calls `reset_session` before doing so. This breaks the intended binding "the session cookie an unauthenticated visitor is carrying == the session cookie that becomes trusted after a successful OAuth login," because the callback reuses whatever session the browser already had instead of minting a fresh one at the authentication boundary.

### Finding Description
`force_github_authentication` (in `app/controllers/concerns/shipit/authentication.rb`) redirects any anonymous visitor to `github_authentication_path`, and Rails will have already assigned that anonymous visitor a session cookie (Shipit's `ApplicationController`/`ShipitController` use `protect_from_forgery` and rely on the default cookie-backed session) [1](#0-0) [2](#0-1) .

When the OAuth provider redirects back, `callback` does:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [3](#0-2) 

Note that `logout` explicitly calls `reset_session` [4](#0-3) , which shows the engine's own authors recognize `reset_session` is the correct primitive at a trust-level transition — yet the *login* path, which is the more sensitive transition (anonymous → authenticated), omits it entirely. `sign_in_github` looks the user up/creates them purely from the OAuth payload and stores the resulting `user.id` into whatever session object is currently active [5](#0-4) .

`current_user` and every authorization decision in the app (`force_github_authentication`, team checks, `ApiClient`/session-based UI access) are derived solely from `session[:user_id]` [6](#0-5) . Because the session identifier itself is never rotated at the moment identity is bound, an attacker who can get a victim's browser to carry a session established by the attacker (classic fixation, e.g. by planting the cookie via a shared/subdomain-writable cookie or by having the victim start a session on the attacker's timing) will end up sharing the resulting authenticated session with the victim once the victim completes the GitHub OAuth login in that same session — i.e. the "GitHub identity that authenticated" is bound to a session whose identifier the attacker already controls, rather than to a freshly issued one tied uniquely to that authentication event.

### Impact Explanation
This maps to the listed High-impact bucket "session fixation / forced OAuth completion." If an attacker can pre-establish/fix the session cookie in the victim's browser and induce the victim to complete the GitHub OAuth flow, the attacker gains a session bound to the victim's `Shipit::User` (`session[:user_id]`), which grants read of stack/task state, ability to trigger deploys/rollbacks/tasks the victim is authorized for, and access to any `ApiClient` management pages the victim can reach — an authentication-boundary violation as defined by the rules (unauthorized deploy/rollback capability and escalation into the victim's `Shipit.github_teams`-derived authorization).

### Likelihood Explanation
Exploitation requires the attacker to get a chosen session identifier into the victim's browser before the victim authenticates (a standard session-fixation prerequisite — e.g. cookie scoping issues, a shared host, or a network position that can set a cookie), then get the victim to complete the OAuth login. This is a real but non-trivial precondition; it does not require any secret, API token, or repository access, matching the "unprivileged attacker" scope of this exercise. The vulnerability is concretely present in code (missing `reset_session`), not speculative.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` immediately before (or as part of) setting `session[:user_id]`/`session[:authenticated]`, exactly as is already done in `logout`, so a brand-new session is always minted at the point an OAuth identity becomes trusted.

### Proof of Concept
1. Attacker visits the Shipit instance anonymously and notes/fixes the session cookie value (e.g. via a subdomain that can set cookies for the parent domain, or any mechanism that plants a chosen session cookie in the victim's browser).
2. Attacker gets the victim to open a Shipit URL while carrying that fixed session cookie, triggering `force_github_authentication` → redirect to `/github/auth/github`.
3. Victim completes the real GitHub OAuth flow; `GithubAuthenticationController#callback` runs `session[:user_id] = sign_in_github(auth)` without calling `reset_session`, writing the victim's `user_id` into the same (attacker-known) session [7](#0-6) .
4. Attacker reuses the fixed session cookie and is now authenticated as the victim, per `current_user`'s lookup of `session[:user_id]` [6](#0-5) .

**Note on verification limits:** I could not locate the exact session-store configuration (`config/initializers/session_store.rb` or equivalent) in the indexed portion of the repo, so I cannot confirm from code alone whether Shipit uses the default Rails cookie-store (which somewhat mitigates classic session-ID fixation but is still exposed to "forced OAuth completion"/cookie-tossing variants) or a server-side store (which would make this a textbook session-fixation bug). This is a limitation of the codebase index, not of the underlying finding: the missing `reset_session` in `callback` is confirmed directly in the file cited above regardless of session-store backend.

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

**File:** app/controllers/shipit/shipit_controller.rb (L16-26)
```ruby
    before_action :ensure_required_settings

    include Shipit::Authentication

    # Respond to HTML by default
    respond_to :html

    # Prevent CSRF attacks by raising an exception.
    # For APIs, you may want to use :null_session instead.
    protect_from_forgery with: :exception

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

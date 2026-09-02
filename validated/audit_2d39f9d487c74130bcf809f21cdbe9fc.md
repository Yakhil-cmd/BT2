## Analysis Summary

Mapping the "double-voting" bug class (an action taken *after* an authorization check succeeds, on state that has since diverged from what was verified) to this engine, the strongest analog is a **session fixation** flaw in the OAuth login flow: the binding that should hold is `session id before login == session id after login is invalidated`, but `GithubAuthenticationController#callback` never calls `reset_session` when completing a login, unlike `#logout`, which does. [1](#0-0) [2](#0-1) 

### Title
Session Fixation on GitHub OAuth Login — ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` binds an authenticated GitHub identity to the current session by writing `session[:user_id]` and `session[:authenticated]` directly into whatever session already exists, without first calling `reset_session`. `#logout` calls `reset_session`, but the login path does not, breaking the equality "session identifier before authentication == a session identifier that is invalidated at authentication."

### Finding Description
`force_github_authentication` in `Shipit::Authentication` redirects unauthenticated visitors to `github_authentication_path`, which starts the OmniAuth flow. [3](#0-2) 

Once GitHub redirects back, `callback` finds/creates the `User` from `auth.extra.raw_info` and stores the resulting id in the session, reusing the existing session and cookie: [1](#0-0) 

Compare this to `logout`, which explicitly calls `reset_session` before redirecting: [2](#0-1) 

Because the session cookie/id is never rotated on successful login, any session identifier that was set (or known) before authentication remains valid and privileged after authentication completes — exactly the same class of bug as the report's "lock tokens before proposing, so they're unlocked by proposal time" gap: a value considered valid at check-time (the pre-auth session id) is not invalidated by the time the privileged action (binding a `User` to the session) occurs.

### Impact Explanation
An attacker who can plant a known session identifier in a victim's browser before the victim authenticates (e.g. via response-splitting on a shared parent domain, a network/proxy that fixes cookies, or any mechanism setting the Shipit session cookie prior to login) can then use that same session id/cookie after the victim completes GitHub OAuth login to access the victim's authenticated Shipit session — i.e., session fixation, one of the explicitly recognized High-impact classes for this engine (escalation into an authenticated user's session).

### Likelihood Explanation
The pattern is directly visible in the code: `reset_session` is called on `logout` but not on `callback`/login, so any environment where a session cookie can be pre-set for the victim (common with permissive cookie scoping, e.g. `domain: '.example.com'` deployments as documented for `Shipit.host`) is exploitable without needing any Shipit credentials, `ApiClient` token, or webhook secret — it only requires the target to complete a normal GitHub login.

### Recommendation
Call `reset_session` (or `session.merge!` after `reset_session`, preserving only the `omniauth.origin` return URL) inside `GithubAuthenticationController#callback` immediately before assigning `session[:user_id]` and `session[:authenticated]`, mirroring the behavior already implemented in `#logout`.

### Proof of Concept
1. Attacker obtains or fixes a session cookie value `S` for the victim's browser (e.g., cookie set for a shared/parent domain before the victim visits Shipit).
2. Victim visits Shipit, is redirected to `/github/auth/github`, completes GitHub OAuth, and lands on `GithubAuthenticationController#callback`.
3. `callback` writes `session[:user_id]` into the *same* session `S` rather than issuing a new session id, because `reset_session` is never invoked.
4. Attacker replays cookie `S` and is now authenticated as the victim in Shipit, since the session was never rotated at login.

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

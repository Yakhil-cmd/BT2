### Title
Session Fixation on GitHub OAuth Callback Allows Session Hijacking - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
The reported bug class is a "verified-credential-to-identity binding" failure: a signature (admin's ed25519 signature) authenticates a *piece of metadata*, but nothing binds that verified metadata to the specific session/wallet that ultimately benefits from it, and the session/authorization can be replayed or reused without expiry or actor binding. The closest reachable analog in Shipit is `Shipit::GithubAuthenticationController#callback`, which authenticates a GitHub identity via OmniAuth and then binds it to the *existing, unrotated* Rack session by writing `session[:user_id]`, instead of establishing a fresh session identifier. This breaks the equality that should hold: `session_id before OAuth completion == session_id after OAuth completion` must not stay `true`, i.e. **the pre-authentication session must not remain valid once bound to a GitHub identity**.

### Finding Description
`GithubAuthenticationController#callback` performs:
```ruby
def callback
  ...
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [1](#0-0) 

It writes the authenticated user's identity directly into the *current* session object without calling `reset_session` (contrast with `logout`, which does call `reset_session`, and with `force_github_authentication`, which calls `reset_session` when detecting a stale login) [2](#0-1) [3](#0-2) .

Downstream, `Shipit::Authentication#current_user` and `#find_current_user` trust `session[:user_id]` unconditionally to resolve the acting `User` for every authenticated engine controller [4](#0-3) . Because the session identifier/cookie established *before* login is preserved and simply "upgraded" in place after OmniAuth completes, an attacker who can get a victim to authenticate under a session the attacker already controls (a session-fixation precondition) ends up sharing full access to the victim's authenticated `User` record — mirroring the report's core defect: a verification step (GitHub OAuth / admin signature) succeeds, but the thing that is supposed to be scoped by it (the specific session / specific wallet) is never re-bound or invalidated, so a previously-obtained artifact (a fixated session / a signature) keeps working after the trust boundary should have reset it.

### Impact Explanation
If the pre-login session is not rotated on successful OAuth callback, an attacker-controlled session cookie fixated onto a victim before login becomes a live, fully-authenticated `Shipit::User` session after the victim completes GitHub OAuth — i.e., **session fixation / forced OAuth completion**, which is explicitly listed as a High-impact category (escalation into authenticated state without possessing the victim's GitHub credentials). This allows the attacker to act as the victim across every engine feature gated by `current_user` (deploys, rollbacks, locks, merge requests, API client creation) depending on the victim's `Shipit.github_teams` membership.

### Likelihood Explanation
Exploitability hinges entirely on whether the fixation precondition (attacker being able to set the session identifier that the victim's browser will use before authentication) is achievable, and the app's session-store configuration (`config/initializers/session_store.rb` in the host app, not part of this engine) is what determines whether the session cookie carries a rotatable server-side ID or is a self-contained signed value. This engine does not control or document the session store choice, so likelihood is store-dependent and could not be fully confirmed from the engine code alone (the test dummy's session store initializer was located but its content, and thus the deployed default, was not inspected in depth). Given this uncertainty, and because the missing `reset_session` in `callback` is the only concrete code-level omission found that maps to the report's "no rebinding/invalidation of a verified credential to its intended holder" defect, this should be treated as a real but conditional finding.

### Recommendation
Call `reset_session` at the start of `GithubAuthenticationController#callback`, before assigning `session[:user_id]` and `session[:authenticated]`, so a new session is always issued on successful authentication — mirroring the pattern already used in `logout` and in `force_github_authentication`'s stale-login handling.

### Proof of Concept
1. Attacker visits the Shipit instance anonymously and obtains a session cookie/identifier (pre-authentication).
2. Attacker fixates that same session identifier onto the victim's browser (precondition dependent on session-store/cookie configuration outside this engine).
3. Victim completes the GitHub OAuth flow; `GithubAuthenticationController#callback` sets `session[:user_id]` on the *same, unrotated* session without calling `reset_session` [1](#0-0) .
4. Attacker, still holding the original session identifier, is now recognized as the victim by `Shipit::Authentication#find_current_user` [5](#0-4)  and can perform any action the victim is authorized for.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-24)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
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

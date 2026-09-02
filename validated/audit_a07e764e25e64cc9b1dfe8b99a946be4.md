### Title
Session Fixation on GitHub OAuth Callback Enables Authentication Bypass - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds a freshly-authenticated GitHub identity to the *existing* Rack session without regenerating the session identifier first. An unauthenticated attacker who fixates a victim's session cookie before the victim completes GitHub OAuth ends up owning the same session ID that becomes bound to the victim's `User` record, hijacking the victim's authenticated Shipit session. This is the direct analog of the reported bug class: instead of properly re-establishing ("assigning") a fresh trust binding at the moment of privilege change, the code merely writes into a pre-existing, unverified state (the old session), letting an attacker who set up that state beforehand inherit the elevated binding.

### Finding Description
The OAuth callback handler is: [1](#0-0) 

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']

  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
```

There is no `reset_session` call prior to writing `session[:user_id]`. Compare this to `logout`, which does call `reset_session`: [2](#0-1) 

The trust binding that authorization depends on is `session[:user_id]` resolving to a `User`, consumed everywhere via `current_user`: [3](#0-2) 

Because the *session identifier itself* is never rotated on login, the equality that should hold — "the session ID an attacker can fixate" ≠ "the session ID bound to the victim's GitHub identity after login" — is violated: they become the same session ID. This mirrors the reported bug's root cause (a verification/consistency check omitted where a proper state update/reset was required), just applied to session lifecycle instead of a claims mapping.

### Impact Explanation
If an attacker can set the Shipit session cookie in a victim's browser prior to the victim completing GitHub OAuth (a standard session-fixation delivery, e.g. via a crafted link that sets a cookie for the Shipit host, or a shared-domain cookie write), and the victim subsequently authenticates through `github_authentication_controller#callback`, the attacker's known session ID becomes bound to `session[:user_id]` of the victim's `User`. The attacker can then use that same session ID to act as the victim inside Shipit — reading stack/task state, triggering deploys/rollbacks, or any action gated only by `current_user`/`Shipit.github_teams` authorization. This matches the rules' explicitly accepted High-impact class: "session fixation / forced OAuth completion."

### Likelihood Explanation
The engine explicitly demonstrates awareness of session-reset hygiene elsewhere (`logout` and `force_github_authentication`'s `reset_session` call on stale credentials): [4](#0-3) 

but the OAuth `callback` — the single most security-critical transition point, where an anonymous session becomes an authenticated one — omits it. No credentials, tokens, or privileged access are needed by the attacker; only the ability to get a victim to complete a normal login flow while carrying an attacker-chosen session cookie, which is the standard session-fixation precondition.

### Recommendation
Call `reset_session` (or otherwise regenerate the session ID) in `GithubAuthenticationController#callback` before assigning `session[:user_id]`, mirroring the pattern already used in `logout` and in `force_github_authentication`'s stale-credential branch, e.g.:

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
1. Attacker obtains/observes a valid (unauthenticated) Shipit session cookie value `S` (e.g. by visiting the Shipit host themselves, or by any mechanism that lets them fix a known session ID into the victim's browser for the Shipit domain).
2. Attacker gets the victim to browse Shipit with session cookie `S` set, then complete the GitHub OAuth login flow (`/github/auth/github` → GitHub → `/github/auth/github/callback`).
3. `GithubAuthenticationController#callback` executes `session[:user_id] = sign_in_github(auth)` without regenerating the session, so session `S` is now bound to the victim's `User` record and marked `session[:authenticated] = true`.
4. Attacker reuses cookie `S` against Shipit and is now treated as the victim by `current_user` in `app/controllers/concerns/shipit/authentication.rb`, gaining the victim's authorization level (e.g. deploy/rollback/merge permissions per `Shipit.github_teams`). [5](#0-4)

### Citations

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-34)
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

    def logout
      reset_session
      redirect_to(root_path)
    end

    private

    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
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

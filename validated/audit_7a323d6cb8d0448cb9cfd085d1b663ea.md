### Title
Session Fixation in GitHub OAuth Callback — Authenticated Identity Bound to Pre-Existing Session ID - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` binds the newly-authenticated GitHub identity to whatever session already exists in the browser, without ever calling `reset_session` first. This is the same class of bug as the ECG report: a piece of protocol/application state (the guild-holder's weight / here, the session identifier) is allowed to persist across a trust-boundary transition (offboarding / here, anonymous → authenticated) without being invalidated, letting an attacker who controls the "before" state siphon the benefit of the "after" state.

### Finding Description
The equality that should hold is: `session_id after OAuth login == freshly regenerated session_id`, i.e. the `User` bound to a session after login must never be the same session identifier that existed before authentication. Instead, the engine currently guarantees only: `session[:user_id] after login == github identity from omniauth`, with no invalidation of the underlying session cookie/id itself.

```ruby
# app/controllers/shipit/github_authentication_controller.rb
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']

  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true

  redirect_to(return_url)
end
``` [1](#0-0) 

Note that `reset_session` is only ever called in two other places: on `logout`, and when `force_github_authentication` detects a stale/legacy `github_access_token` and forces re-login:
```ruby
def logout
  reset_session
  redirect_to(root_path)
end
``` [2](#0-1) 

```ruby
def force_github_authentication
  if current_user.logged_in? && current_user.requires_fresh_login?
    Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
    reset_session
    redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
  ...
``` [3](#0-2) 

The successful OAuth `callback` path — the actual privilege-elevation event (anonymous → authenticated `User`) — is the one place that should regenerate the session, and it is exactly the one place that doesn't. `current_user` is derived purely from `session[:user_id]`:
```ruby
def find_current_user
  session[:user_id].present? && User.find_by(id: session[:user_id])
end
``` [4](#0-3) 

Because the session id itself is never rotated at login, any session identifier that existed prior to the OAuth handshake remains valid and becomes "logged in" as soon as `sign_in_github` writes `user_id` into it. `sign_in_github` also persists the victim's `github_access_token` onto that `User` record:
```ruby
def sign_in_github(auth)
  user = User.find_or_create_from_github(auth.extra.raw_info)
  user.update(github_access_token: auth.credentials.token)
  user.id
end
``` [5](#0-4) 

### Impact Explanation
This maps to the explicitly accepted High-impact category "session fixation / forced OAuth completion." If an attacker can plant/fix a session cookie in a victim's browser prior to the victim completing the GitHub OAuth flow (a standard session-fixation delivery vector — e.g. cookie scoping across a shared parent domain, a response that sets a cookie the attacker chose, or getting the victim to click a login link with the attacker's session already loaded), the attacker's known session id becomes authenticated as the victim once the victim finishes the OAuth dance. The attacker can then reuse that same session id to access Shipit as the victim: trigger deploys/rollbacks, read stack/task output, and act with the victim's `github_access_token`-backed privileges (via `github_api`) — an unauthorized deploy/rollback and effectively an authentication bypass of the victim's identity, without ever needing the victim's password, the app's `webhook_secret`, `api_clients_secret`, or GitHub App private key.

### Likelihood Explanation
Medium-High. No privileged credential, API token, or webhook secret is required from the attacker — only the ability to fixate a session id in the victim's browser and get the victim to complete an OAuth login (a well-known class of attack against Rails apps that don't call `reset_session` on login). The absence of `reset_session` in `callback`, contrasted with its deliberate presence in `logout` and the stale-token re-auth path, shows the omission is a genuine gap rather than a deliberate design choice.

### Recommendation
Call `reset_session` (or otherwise regenerate the session id) at the start of `GithubAuthenticationController#callback`, before writing `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and in `force_github_authentication`'s stale-login branch:
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
1. Attacker visits the Shipit instance anonymously and obtains a session cookie `S1` (no `user_id` set yet).
2. Attacker fixes `S1` into the victim's browser (e.g., via any mechanism that lets the attacker set a cookie on the app's domain — subdomain cookie scoping, a network position that can inject a `Set-Cookie`, or simply sending the victim a crafted login link if the app ever echoes/accepts a session id in the URL/cookie before authentication).
3. Victim, using session `S1`, clicks "Sign in with GitHub" and completes the OmniAuth flow.
4. `GithubAuthenticationController#callback` writes `session[:user_id] = <victim's user id>` into session `S1` without rotating the session id.
5. Attacker, still holding cookie `S1`, is now authenticated as the victim and can trigger deploys/rollbacks, view task streams, and act through the victim's stored `github_access_token`. [1](#0-0)

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
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

**File:** app/controllers/concerns/shipit/authentication.rb (L40-42)
```ruby
    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

### Title
Session Fixation on GitHub OAuth Callback Allows Account Takeover - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`Shipit::GithubAuthenticationController#callback` binds `session[:user_id]` to the `User` resolved from the GitHub OAuth response without first rotating the session identifier. Because the session ID is never regenerated on login, an attacker who fixates a known session ID in a victim's browser before the victim completes the GitHub OAuth flow ends up sharing an authenticated session with the victim, gaining full access to the victim's Shipit account (including their `github_access_token`).

### Finding Description
The binding that must hold is: `session_id used before authentication == session_id trusted after authentication` should never be true across a privilege boundary — i.e., completing login must issue a *new* session identifier so that any pre-existing (potentially attacker-controlled) session cookie cannot be "promoted" to an authenticated one.

In `callback`, the controller writes the identified `User#id` directly into the existing session without calling `reset_session`: [1](#0-0) 

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

Compare this with `logout`, which does call `reset_session`: [2](#0-1) 

`reset_session` is used exactly once elsewhere in the engine, inside `Shipit::Authentication#force_github_authentication`, when an already-authenticated user is detected as needing a fresh login — but it is never invoked at the moment a *new* login is granted: [3](#0-2) 

Downstream, `current_user` trusts whatever `session[:user_id]` contains: [4](#0-3) 

Because Rails' cookie/session store does not rotate the session ID automatically on writes, an attacker who can pre-set a known session cookie in the victim's browser (e.g., by hosting a page under a shared parent domain that sets a cookie for the app's domain, or exploiting a fixation vector before the victim ever visits Shipit) can:
1. Visit Shipit and note the session cookie value (or force it via cookie tossing), while unauthenticated.
2. Get the victim to open Shipit using that same forced session cookie and complete the real GitHub OAuth login.
3. Because `callback` never rotates the session ID, the attacker's known cookie is now bound to `session[:user_id] = <victim's User id>`.
4. The attacker replays that cookie and is now authenticated as the victim, inheriting their `github_access_token` (used for `github_api` calls) and their team/authorization membership.

### Impact Explanation
This is a session fixation leading to full account takeover of a legitimate Shipit user, without needing any Shipit session, API token, or webhook secret from the attacker beforehand — only the ability to plant a session cookie value that the victim's browser will later use. Once fixated, the attacker inherits the victim's authenticated session, including `current_user.github_access_token` used by `User#github_api` for GitHub API calls performed on the victim's behalf, and any deploy/merge authorization the victim holds via `Shipit.github_teams`. This matches the explicitly in-scope High-impact class of "session fixation / forced OAuth completion."

### Likelihood Explanation
The missing `reset_session` on login is a straightforward, always-present code path — every successful OAuth callback goes through it, and the vulnerable line is unconditionally reachable by any user completing OAuth. The main constraint is the attacker's ability to fixate a cookie in the victim's browser (e.g., cookie scoping issues, subdomain cookie tossing, or an app deployed without `secure`/proper cookie domain scoping), which is a common real-world condition for Rails apps that don't explicitly guard against fixation. Given the engine relies entirely on the host app's session configuration and provides no explicit protection itself, likelihood is Medium-High for any deployment lacking additional session-fixation mitigations.

### Recommendation
Call `reset_session` (or explicitly regenerate the session ID) inside `GithubAuthenticationController#callback` immediately before writing `session[:user_id]`, mirroring what is already done in `logout` and in `Authentication#force_github_authentication`. For example:

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
1. Attacker visits `/github/auth/github` on the target Shipit instance and captures the session cookie issued before authentication (or fixes a chosen session cookie value via a cookie-tossing/subdomain technique against the app's cookie scope).
2. Attacker sends the victim a link to the Shipit app while ensuring the victim's browser carries that same session cookie.
3. Victim completes the real GitHub OAuth flow; `GithubAuthenticationController#callback` sets `session[:user_id] = <victim id>` on the (unrotated) session tied to the cookie the attacker already knows.
4. Attacker replays the captured cookie against the Shipit instance and is now treated as the victim by `Authentication#current_user`, gaining access to the victim's stacks, deploy permissions, and `github_access_token`.

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

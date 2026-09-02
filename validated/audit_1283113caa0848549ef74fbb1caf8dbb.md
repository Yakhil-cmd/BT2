### Title
Session fixation via missing session regeneration on GitHub OAuth callback - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds the freshly authenticated GitHub identity into the session by writing `session[:user_id]` directly, without first invalidating/regenerating the pre-existing session. This is the same bug class as H-8: a value (`operand_to_check` / here, "the session that gets bound to the authenticated identity") is trusted for the purpose of authorization decisions without first constraining it to be the value the trust model assumes — a fresh, attacker-unknown session issued for this login.

### Finding Description
The equality the engine's security model relies on is:

`GitHub identity verified by OmniAuth == the session (session[:user_id]) subsequently trusted as "current_user" for all further requests` [1](#0-0) 

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

Unlike `logout`, which calls `reset_session` before clearing the cookie, `callback` never resets/regenerates the session prior to writing `session[:user_id]`. Once a `User` record is resolved via `sign_in_github` (`User.find_or_create_from_github`), the resulting `user_id` is written into whatever session the browser already presented, and `current_user` in `Shipit::Authentication` trusts that value for every subsequent authorization decision (team membership check, deploy permission, etc.): [2](#0-1) 

An attacker who can cause a target session identifier to exist in the victim's browser before the victim completes GitHub login (classic session fixation — no Shipit session, token, or GitHub credential is needed by the attacker to set this up, only the ability to plant/predict a session cookie value, e.g. via a shared/parent-domain cookie scope or a lower-severity cookie-setting bug elsewhere on the same top-level domain) can subsequently use that same session cookie to inherit the victim's authenticated identity, because the login flow never rotates the session id/state before trusting it.

### Impact Explanation
If exploited, this allows an attacker to hijack an authenticated Shipit session belonging to a legitimate, team-authorized GitHub user without ever presenting valid GitHub credentials themselves — i.e., authentication bypass / session fixation, explicitly listed as an in-scope High-impact class. Once the victim's identity is bound to the attacker-controlled session, the attacker inherits whatever privileges (`Shipit.github_teams` membership, deploy/rollback/merge rights) the victim's `User` record carries.

### Likelihood Explanation
The root cause (missing `reset_session` before writing `session[:user_id]`) is present unconditionally on every OAuth callback and requires no privileged credential, matching the report's "no internal/external pre-conditions" characterization. The realistic constraint is the attacker's ability to plant a specific session identifier into the victim's browser ahead of time, which is an environment-dependent precondition but is the standard precondition for any session-fixation finding, and is exactly the impact category the rules call out as acceptable ("session fixation / forced OAuth completion").

### Recommendation
Call `reset_session` (or otherwise regenerate the session id) in `GithubAuthenticationController#callback` before assigning `session[:user_id]` and `session[:authenticated]`, so that a freshly authenticated identity is always bound to a newly issued session rather than to whatever session the browser presented pre-authentication.

### Proof of Concept
1. Attacker obtains/plants a specific session cookie value for the Shipit host in the victim's browser (session fixation precondition).
2. Attacker sends the victim a link to `/github/auth/github` (login start) on the fixed session.
3. Victim completes the real GitHub OAuth flow; `GithubAuthenticationController#callback` runs and executes `session[:user_id] = sign_in_github(auth)` on the same (fixed) session id, without calling `reset_session`.
4. Attacker, already holding that same session cookie, now sends requests as the victim's `User`, inheriting `Shipit.github_teams` authorization and deploy/rollback/merge capabilities. [3](#0-2)

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

**File:** app/controllers/concerns/shipit/authentication.rb (L36-42)
```ruby
    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

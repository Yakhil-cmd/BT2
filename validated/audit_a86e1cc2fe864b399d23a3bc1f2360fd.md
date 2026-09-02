### Title
Session Fixation on GitHub OAuth Callback Due to Missing Session Regeneration - ([File: `app/controllers/shipit/github_authentication_controller.rb`])

### Summary
### Finding Description
The bug class in the referenced report is that a state-changing operation (a token transfer) proceeds unconditionally on an attacker-controlled precondition (a zero fee) instead of first validating/resetting that precondition. The structural analog in `shipit-engine` is `GithubAuthenticationController#callback`, which binds a freshly-verified GitHub identity to the *existing* session without first invalidating (rotating) that session: [1](#0-0) 

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

Compare this to `#logout`, which correctly calls `reset_session` before discarding state: [2](#0-1) 

The binding that should hold as an equality is:

`session identifier before OAuth completion == session identifier after OAuth completion` must be **false** (i.e., the session must be rotated on privilege/identity change), the same way `find_current_user` trusts `session[:user_id]` unconditionally to resolve the authenticated `User`: [3](#0-2) 

Instead, `#callback` writes the verified GitHub identity's `user_id` into whatever session the browser presented, without first calling `reset_session`. This breaks the "GitHub identity vs. `User` bound to the session" binding: any session an attacker managed to plant into a victim's browser prior to authentication remains valid and simply gets re-keyed to the victim's identity once the victim completes the GitHub OAuth flow.

### Impact Explanation
If the session is fixated by an attacker before the victim completes OAuth, and the underlying session store is server-side keyed (e.g., a cache/Redis-backed store, common for Shipit deployments given its Redis dependency), the attacker's pre-established session key becomes bound to the victim's authenticated `User` record post-login. This is listed explicitly as an accepted High-impact class ("session fixation / forced OAuth completion") because it lets an attacker hijack a fully authenticated Shipit session for another GitHub-authorized user, granting access to that user's authorization level (deploys, rollbacks, hooks, API client management) without ever presenting valid GitHub credentials themselves.

### Likelihood Explanation
Exploitability depends on the attacker being able to plant a known session identifier into the victim's browser prior to the victim's OAuth completion (e.g., via a crafted link, response-splitting, or a session ID accepted from the URL/cookie before authentication) and on the host application's session store being server-side keyed rather than a self-contained encrypted cookie. This is a real but not certain precondition — it depends on host-app session store configuration, which is outside the engine's own code, so likelihood is moderate rather than certain. Nonetheless, the root cause (missing `reset_session` in `callback`, present in `logout`) is a concrete, in-scope code defect independent of session-store choice, and is the same pattern that the CWE-384 (Session Fixation) class targets.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before setting `session[:user_id]` and `session[:authenticated]`, mirroring the pattern already used in `#logout`, so that any pre-authentication session is invalidated and a new session is issued upon successful GitHub sign-in:

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
1. Attacker obtains/derives a session identifier and plants it in the victim's browser prior to authentication (e.g., via a crafted callback/redirect link containing the session cookie, or by exploiting a scenario where the session cookie is set before login).
2. Victim visits Shipit and completes the GitHub OAuth flow; `GithubAuthenticationController#callback` executes: [4](#0-3) 
   writing `session[:user_id] = victim.id` into the *same* (attacker-known) session, without rotating it.
3. Attacker reuses the fixated session identifier and is now treated as the authenticated victim by `Authentication#find_current_user`: [5](#0-4) 
   gaining the victim's authorization level across all Shipit engine controllers protected only by `force_github_authentication`.

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

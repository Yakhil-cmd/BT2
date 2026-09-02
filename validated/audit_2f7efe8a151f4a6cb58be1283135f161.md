### Title
Session Fixation on GitHub OAuth Callback Allows Attacker to Hijack a Victim's Authenticated Session - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`Shipit::GithubAuthenticationController#callback` writes the authenticated user's identity into the existing session (`session[:user_id]`, `session[:authenticated]`) without first calling `reset_session`, unlike `#logout` which does. This breaks the binding "GitHub identity that completed OAuth == the `User` object bound to *that specific, attacker-uncontrolled* session," analogous to the ClearingHouse report's failure to validate identity/state before trusting a privileged write.

### Finding Description
The callback action is:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']

  return render('failed', layout: false) if auth.blank?

  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true

  redirect_to(return_url)
end
``` [1](#0-0) 

`#logout` explicitly calls `reset_session` before redirecting, showing the engine authors are aware session regeneration is the correct pattern in this controller — but `callback`, the far more security-sensitive action, omits it:
```ruby
def logout
  reset_session
  redirect_to(root_path)
end
``` [2](#0-1) 

Downstream, `Shipit::Authentication#force_github_authentication` and `#current_user` trust `session[:user_id]` as the sole binding between the HTTP session and the `User` record for every privileged page (stacks, deploys, tasks, api_clients, merge requests):
```ruby
def current_user
  @current_user ||= find_current_user || AnonymousUser.new
end

def find_current_user
  session[:user_id].present? && User.find_by(id: session[:user_id])
end
``` [3](#0-2) 

If a session ID were established before OAuth completion (e.g. via a pre-set session cookie), the equality "session-id -> GitHub identity" is never re-established at authentication time because the session is never rotated. This matches the "GitHub identity versus the `User` bound to the session" binding class this scan is instructed to focus on.

### Impact Explanation
If exploited, this allows fixation of a victim's session ID prior to their completing GitHub OAuth login; once the victim authenticates, the attacker — who already knows the (unrotated) session ID — inherits `current_user` as that victim across every `ShipitController` subclass (`StacksController`, `TasksController`, `ApiClientsController`, `MergeRequestsController`, etc.), all of which rely on `Shipit::Authentication#current_user`/`session[:user_id]`. This is a full authenticated-session takeover, matching the explicitly listed High-severity impact "session fixation / forced OAuth completion."

### Likelihood Explanation
The `/github/auth/github/callback` endpoint is reachable unauthenticated by design (it is the login flow itself), so no credential, token, or repository access is required to reach the vulnerable code path — only the ability to get a victim to visit a link with a pre-set/known session cookie and complete GitHub login, which is the standard session-fixation delivery mechanism. I was not able to fully verify from the indexed files whether the surrounding Rails session middleware (e.g., `config/initializers/session_store.rb`, cookie `SameSite`/`secure` flags, or OmniAuth's own state-parameter CSRF protection in `lib/shipit/engine.rb`) provides any additional mitigation, since those configuration files were not returned by search within the available tool budget.

### Recommendation
Call `reset_session` (or explicitly regenerate the session ID, e.g. via `request.session.options[:renew] = true` if some pre-authentication data such as the OmniAuth origin needs to be preserved) inside `GithubAuthenticationController#callback` immediately before assigning `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `#logout`.

### Proof of Concept
1. Attacker obtains or fixes a session cookie value for the victim's browser (e.g., session ID accepted from URL/subdomain cookie scoping, or via any mechanism that lets a session cookie be set before login — the standard session-fixation precondition).
2. Attacker sends the victim a link to `/github/auth/github` with that pre-set session cookie active in the victim's browser.
3. Victim completes GitHub OAuth; `GithubAuthenticationController#callback` runs `session[:user_id] = sign_in_github(auth)` on the *existing* session object rather than a freshly rotated one [4](#0-3) .
4. Attacker, already in possession of the same session ID, now has `current_user` resolved to the victim on every subsequent request through `Shipit::Authentication#find_current_user` [5](#0-4) , gaining full access to deploy/rollback/merge/API-client management as the victim.

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

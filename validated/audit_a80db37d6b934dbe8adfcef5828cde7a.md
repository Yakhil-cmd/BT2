### Title
Session fixation via missing session regeneration on GitHub OAuth login - (`app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds a freshly-authenticated GitHub identity to whatever session ID the browser already presented, without ever rotating that session ID. This breaks the equality that should hold at an authentication boundary: `session_id(before OAuth completes) == session_id(after OAuth completes)` should never be true, yet the code lets it remain true, so a session ID chosen/known before login becomes the authenticated session after login (classic session fixation / forced OAuth completion, an accepted High-impact class in scope).

### Finding Description
The relevant binding is: *GitHub identity that completes OAuth* vs *the `User` bound to the current session*. Elsewhere in the engine, the code is careful to invalidate stale session/identity bindings — `force_github_authentication` explicitly calls `reset_session` when a user's credentials are stale [1](#0-0)  and `logout` also calls `reset_session` [2](#0-1) .

However, the actual login transition — `callback` — never calls `reset_session` before writing the newly authenticated identity into the session: [3](#0-2) 

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

The session's identity is derived only from `session[:user_id]`, checked later by `Authentication#find_current_user`: [4](#0-3) 

Because the session ID itself is never regenerated at the moment `session[:user_id]` transitions from unset (or attacker-controlled) to the victim's ID, any session ID that existed prior to `callback` running (e.g., one an attacker could pre-establish and get the victim to carry into the login flow) becomes a fully authenticated session for the victim's identity once the OAuth dance completes.

### Impact Explanation
If an attacker can get their own (pre-known) session cookie fixed into a victim's browser and then get the victim to complete the GitHub OAuth login on Shipit, the attacker can reuse that same session cookie to be logged in as the victim. Since Shipit sessions grant the full authenticated `User` context (`current_user`), this yields full account takeover of the victim inside Shipit: read of stack state, task streams, deploy output, and the ability to trigger deploys/rollbacks/locks that the victim is authorized for. This satisfies the in-scope "session fixation / forced OAuth completion" High-impact category, and depending on the victim's privileges could enable an unauthorized deploy/rollback (Critical).

### Likelihood Explanation
Exploitation requires no Shipit session, ApiClient token, webhook secret, or GitHub credentials from the attacker — only the ability to plant/observe a session identifier in the victim's browser prior to the victim completing a normal GitHub login (a well-known session-fixation prerequisite, e.g. via cookie injection on a shared/parent domain, response splitting, or an attacker-supplied link that carries a fixed session id if the session store/cookie configuration allows it). The core code defect — omission of `reset_session` specifically in the login-completion path, while it is present in the logout and stale-credential paths — is a concrete, reachable root cause in engine code, not a theoretical note.

### Recommendation
Call `reset_session` (or otherwise rotate the session ID) in `GithubAuthenticationController#callback` before writing `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and `force_github_authentication`, so that a new session ID is always issued at the moment a session becomes authenticated.

### Proof of Concept
1. Attacker obtains/fixes a session cookie value `S1` (e.g., via a subdomain cookie-tossing vector or any mechanism causing the victim's browser to carry `S1` for the Shipit domain) before the victim is authenticated.
2. Attacker lures the victim to Shipit's `github_authentication` login flow; the victim completes a legitimate GitHub OAuth login.
3. `GithubAuthenticationController#callback` executes `session[:user_id] = sign_in_github(auth); session[:authenticated] = true` on the existing session `S1` — no `reset_session` occurs. [5](#0-4) 
4. Attacker now presents cookie `S1` and is treated as the authenticated victim by `Authentication#find_current_user`. [6](#0-5)

### Citations

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

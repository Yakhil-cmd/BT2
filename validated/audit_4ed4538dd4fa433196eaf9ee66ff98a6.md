### Title
Session Fixation in GitHub OAuth Callback — Session ID Not Rotated on Login (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds the authenticated GitHub identity to the existing Rack session by writing `session[:user_id]` and `session[:authenticated]` directly, without first calling `reset_session`. Every other privilege-boundary transition in the engine (`logout`, and `force_github_authentication` when it detects stale credentials) explicitly calls `reset_session` before or instead of touching the session identity. The callback is the one place where a brand new authenticated identity is bound to a session without rotating the session ID, breaking the equality "GitHub identity just authenticated via OmniAuth == `User` newly bound to *this* session" — the session container itself is never renewed, so any pre-existing (potentially attacker-fixated) session silently inherits full authenticated privileges of whichever GitHub account completes the flow next.

### Finding Description [1](#0-0) 

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

Compare with the two other places in the engine that transition session privilege:

- `logout` explicitly wipes the session: [2](#0-1) 
- `force_github_authentication` calls `reset_session` when it discovers the bound user requires a fresh login, precisely because reusing session state across a credential/identity change is considered dangerous: [3](#0-2) 

Only the `callback` action — the one action that actually establishes a *new* authenticated identity from an external OAuth exchange — omits this rotation. `current_user` is derived purely from `session[:user_id]`: [4](#0-3) , so whoever controls the session container after `callback` runs is treated as that GitHub user for every subsequent request, including deploys, rollbacks, and merges gated by `Shipit.github_teams` authorization in `User#authorized?` [5](#0-4) .

This is the same bug class as the external report: a downstream trust decision (which `User` a session acts as) is made using a value (`session[:user_id]`, computed from `sign_in_github(auth)`) that is bound to a container (the session ID) whose integrity is never re-verified/re-established at the point of privilege elevation, exactly as the IBC report flagged fields accepted into `Entry` without verifying the channel identifiers backing them.

### Impact Explanation
If an attacker can cause a known session identifier to exist in a victim's browser prior to the victim completing the GitHub OAuth login (e.g. any means of fixing a session cookie value), the attacker's pre-existing session — including any `state` OmniAuth stored for CSRF protection — is reused verbatim by `callback`. Once the victim (an authorized org member) completes the GitHub authorization step, `session[:user_id]` is written into that same, attacker-controlled session container. The attacker, holding the same session ID, becomes fully authenticated as the victim, inheriting `Shipit.github_teams` authorization and the ability to trigger deploys/rollbacks/merges as that user — this is the "session fixation / forced OAuth completion" impact explicitly recognized as High severity for this engine.

### Likelihood Explanation
No `ApiClient` token, webhook secret, or GitHub App private key is required — the flaw is purely in how the engine's own controller handles the session container across the login boundary, unlike every sibling code path in the same file/concern which already treats session-identity transitions as requiring `reset_session`. The missing call is a one-line, clearly demonstrable omission rather than a theoretical concern, and it directly contradicts the pattern the codebase itself uses elsewhere for identical purposes.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before assigning `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and `Authentication#force_github_authentication`:

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?

  user_id = sign_in_github(auth)
  reset_session
  session[:user_id] = user_id
  session[:authenticated] = true

  redirect_to(return_url)
end
```

### Proof of Concept
1. Attacker obtains a fresh, unauthenticated Shipit session cookie (e.g. by visiting the Shipit host) and notes its value/session ID.
2. Attacker fixes that same session identifier into the victim's browser (any session-fixation delivery vector applicable to the deployment).
3. Attacker (or the victim, tricked via a crafted link) initiates `/github/auth/github` under that fixed session, then the victim completes GitHub's OAuth consent screen as themselves.
4. `GithubAuthenticationController#callback` writes `session[:user_id] = <victim's User id>` into the still-fixed session container without rotating it.
5. Attacker, holding the same (never-rotated) session ID, is now authenticated as the victim on Shipit and inherits their `Shipit.github_teams` authorization for deploys/rollbacks/merges.

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

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
    end
```

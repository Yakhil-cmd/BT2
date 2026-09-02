## Title
Session fixation via missing session ID regeneration on GitHub OAuth login - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`Shipit::GithubAuthenticationController#callback` binds a newly authenticated GitHub identity to the *existing* session without first regenerating the session identifier. This breaks the intended binding between "the session the user was issued before authenticating" and "the session that is authorized to act as that user after authenticating," making the controller vulnerable to session fixation.

### Finding Description
When a user completes GitHub OAuth, `callback` simply writes into the current session hash: [1](#0-0) 

It never calls `reset_session` (Rails' standard mitigation for session fixation). Contrast this with `logout`, which does call `reset_session`: [2](#0-1) 

All authorization downstream (`Shipit::Authentication#current_user`, permission checks, `ApiClientsController`, `StacksController`, deploy/task triggering, etc.) is derived purely from `session[:user_id]`: [3](#0-2) 

Since the session cookie's underlying identifier is never rotated at the moment privilege is granted, whoever controls the *pre-login* session id also controls the *post-login* session once a victim completes the OAuth dance on that same session. This is precisely the same class of defect as the referenced report: a security-relevant binding (which principal is authorized) is updated (`session[:user_id]` is set) without re-validating/regenerating the underlying trust anchor (the session identifier itself), just as `utilize()` trusted `controller`/`keeper` state without verifying they had actually been set.

### Impact Explanation
This maps to the explicitly listed High-impact bucket "session fixation / forced OAuth completion." A successful fixation results in a fully authenticated session as the victim, granting the attacker whatever the victim's GitHub team membership authorizes inside Shipit (viewing stacks, triggering deploys/rollbacks/tasks, creating `ApiClient`s bound to the victim's account) — i.e., an authentication bypass into the victim's authorized session.

### Likelihood Explanation
Exploitation needs the attacker to get a session cookie with a known/fixed value into the victim's browser before the victim completes GitHub login (e.g., by visiting the Shipit host first to obtain a valid pre-auth session cookie, then getting that value written into the victim's browser context, and inducing the victim to log in). This still requires a delivery vector for the cookie (e.g., shared parent-domain cookie behavior, or the app running on a domain where cookie scoping is broad); the engine code itself provides no protection at the point where it matters (post-login), which is the root cause fixed by `reset_session`.

### Recommendation
Call `reset_session` (or otherwise regenerate the session id) immediately before setting `session[:user_id]`/`session[:authenticated]` in `Shipit::GithubAuthenticationController#callback`, mirroring the pattern already used in `logout`.

### Proof of Concept
1. Attacker visits the Shipit host and obtains a valid, unauthenticated session cookie `S`.
2. Attacker gets cookie `S` set in the victim's browser (e.g. via a cookie-tossing vector on a shared parent domain / subdomain, or any mechanism that allows setting a cookie for the app's domain without XSS on the app itself).
3. Victim, using cookie `S`, is induced to visit `/github/auth/github` and completes the real GitHub OAuth flow.
4. `GithubAuthenticationController#callback` fires: `session[:user_id] = sign_in_github(auth)` is written into session `S` — the same session the attacker already holds — because `reset_session` was never called.
5. Attacker now uses cookie `S` to access Shipit fully authenticated as the victim, per `Shipit::Authentication#find_current_user` at [4](#0-3) .

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

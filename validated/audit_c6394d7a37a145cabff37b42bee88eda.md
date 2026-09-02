### Title
Session fixation on GitHub OAuth login — missing `reset_session` before binding authenticated identity - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` writes the authenticated GitHub identity into the *existing* session (`session[:user_id]`, `session[:authenticated]`) without first calling `reset_session`, unlike `#logout`, which explicitly resets the session. This mirrors the "approve(0) first" class of bug: a security-relevant value (session privilege) is changed in place instead of being cleared/reset before the new trusted value is written, leaving pre-existing (attacker-controlled) session state intact across the trust boundary.

### Finding Description
The equality that should hold after a successful OAuth callback is:

`session identifier issued to the authenticated GitHub identity == a freshly minted session, never previously usable by anyone else`

Before vs after the callback:
- Before: an attacker can obtain/establish a session cookie (unauthenticated) for the victim's browser (e.g., by getting the victim to visit a Shipit URL with a session the attacker already knows, a classic session-fixation setup).
- After the victim completes GitHub OAuth, `callback` runs: [1](#0-0) 
It sets `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` directly on the *pre-existing* session object, without calling `reset_session` first. Contrast this with `#logout`, which does call `reset_session`: [2](#0-1) 

Because the session ID is not rotated at the point privilege is granted (only `session[:user_id]`/`session[:authenticated]` values are mutated), a session ID that was valid (but anonymous) before authentication remains valid and becomes privileged after authentication — the attacker's fixed session id becomes bound to the victim's GitHub identity. Downstream, `current_user` and `find_current_user` in the `Authentication` concern trust `session[:user_id]` unconditionally to resolve the authenticated `User`: [3](#0-2) 

This is the same "missing zero-out before applying new state" root cause referenced by the report — the code path that authenticates modifies session state in place instead of clearing it first, breaking the deployment-trust binding between "the GitHub identity that authenticated" and "the session actually granted".

### Impact Explanation
If an attacker can fixate the session cookie used by a victim's browser prior to the OAuth callback, they gain a fully authenticated session for that victim once the victim completes login — i.e., session fixation / forced OAuth completion, matching the High-severity impact category defined for this scan (escalation into an authenticated session without possessing the victim's GitHub credentials).

### Likelihood Explanation
This requires the classic session-fixation precondition (attacker able to plant/predict a session identifier that the victim's browser will use, e.g. via non-`HttpOnly`/injectable cookie or a shared/pre-set session before login). Given that is satisfied, no other secret or privileged action is required — the callback path itself does the rest, since it never invalidates or rotates the pre-authentication session.

### Recommendation
Call `reset_session` (or otherwise rotate the session identifier) in `GithubAuthenticationController#callback` before assigning `session[:user_id]` and `session[:authenticated]`, mirroring what is already done in `#logout`. This severs any pre-authentication session state from the newly authenticated identity.

### Proof of Concept
1. Attacker obtains an anonymous Shipit session cookie/session id (e.g., by visiting the site themselves, or through any mechanism letting them set/predict the victim's session cookie).
2. Attacker causes the victim's browser to use that same session (classic fixation delivery).
3. Victim navigates to Shipit and completes GitHub OAuth login; `GithubAuthenticationController#callback` fires and sets `session[:user_id]`/`session[:authenticated] = true` on the *existing* (attacker-known) session — no `reset_session` occurs. [4](#0-3) 
4. Attacker now reuses the same session id/cookie and is treated as the authenticated victim by `current_user`/`find_current_user`. [3](#0-2)

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

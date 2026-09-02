### Title
Session fixation on GitHub OAuth callback due to missing `reset_session` before binding `session[:user_id]` - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` binds an authenticated `User` to the current session by setting `session[:user_id]` and `session[:authenticated]`, but it never calls `reset_session` before doing so. [1](#0-0)  This mirrors the report's root cause: a privileged write (here, binding a `User` identity to a session) is performed on an identifier (`session[:user_id]`) that was never verified to belong to the current, pre-authentication context, exactly like `removeCollateralWLpTo` acting on a `tokenId` never checked against the calling position.

### Finding Description
The equality that should hold is: `session_id used for the authenticated session == session_id whose lifecycle began at the moment of GitHub identity verification`. Before authentication, `Shipit::Authentication#current_user` reads `session[:user_id]` [2](#0-1)  and unauthenticated visitors get an `AnonymousUser` and are redirected to `github_authentication_path`. When the OAuth callback fires, `sign_in_github(auth)` resolves/creates a `User` from the raw GitHub payload and the controller simply assigns `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` onto whatever session already existed for that browser/session id [1](#0-0) . Unlike `logout`, which explicitly calls `reset_session` [3](#0-2) , `callback` never regenerates the session before writing the new identity into it. This is the exact analog of the report: the write (`session[:user_id] = ...`) trusts the pre-existing session container without first verifying/resetting that the container is not one an attacker pre-established (fixed) for the victim, just as `removeCollateralWLpTo` trusted `_tokenId` without verifying it belonged to `_posId`.

### Impact Explanation
If an attacker can get a victim's browser to carry a session identifier chosen or known by the attacker prior to authentication (a classic session-fixation precondition), the attacker can then pre-load that session, wait for the victim to complete GitHub OAuth login, and inherit the resulting authenticated `session[:user_id]`/`session[:authenticated]` state — effectively hijacking the victim's post-login session without ever obtaining the victim's GitHub credentials or Shipit cookie. This falls squarely under the explicitly allowed High-impact category "session fixation / forced OAuth completion," since it lets an unprivileged attacker escalate into an authenticated Shipit session bound to another GitHub identity.

### Likelihood Explanation
The vulnerability's exploitability depends on the session-storage mechanism chosen by the host application that mounts the engine (e.g., a server-side session store keyed by session id vs. Rails' default all-in-cookie `CookieStore`, which is comparatively more resistant to classic fixation because the whole session payload — not just an id — is cryptographically bound to `secret_key_base`). This is a factor outside the engine's control. However, the root-cause omission — failing to call `reset_session` at the authentication boundary — is squarely a defect in the engine's own controller code, independent of the host's session-store choice, and is a well-known, widely-flagged anti-pattern for OmniAuth callback actions.

### Recommendation
Call `reset_session` at the start of `GithubAuthenticationController#callback`, before assigning `session[:user_id]`/`session[:authenticated]`, so that a fresh session is always issued at the moment a GitHub identity is bound, mirroring the mitigation already present in `logout`.

### Proof of Concept
1. Attacker obtains (or, depending on host session-store configuration, fixes) a session identifier value, e.g., by visiting the Shipit host and capturing the session cookie issued before login, then delivering that same cookie value to the victim (e.g., via a subdomain that can set cookies for the parent domain, or any mechanism that lets the attacker plant a pre-auth session onto the victim's browser).
2. Victim, using the attacker-known session, visits Shipit and completes GitHub OAuth login via `/github/auth/github/callback`.
3. `GithubAuthenticationController#callback` sets `session[:user_id]` and `session[:authenticated] = true` on the existing (attacker-known) session without regenerating it. [4](#0-3) 
4. Attacker reuses the previously known session identifier/cookie value and is now recognized by `Shipit::Authentication#current_user` as the victim's authenticated `User`. [2](#0-1) 

Note: I was not able to fully verify, within the available index, the exact OmniAuth strategy configuration in `lib/shipit/engine.rb` (e.g., whether `state`-parameter CSRF protection is enabled for the OAuth2 strategy) or the exact session-store class the host app is expected to configure; these are host-application-level decisions outside this engine's own code, and confirming them would require a full Devin session against the complete repository/configuration.

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

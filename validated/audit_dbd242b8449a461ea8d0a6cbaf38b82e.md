## Title
Session Fixation via GitHub OAuth Callback Not Rotating the Session ID - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
The Stableswap `ensure` bug shows a security-relevant guard (deadline enforcement) that is silently missing from the code path that finally commits to an action. In Shipit's OAuth login flow, the analogous missing guard is a call to `reset_session` (or equivalent session-ID rotation) after a successful GitHub authentication. `GithubAuthenticationController#callback` writes `session[:user_id]` and `session[:authenticated] = true` directly into whatever session the browser presented, without ever regenerating the session identifier first.

### Finding Description
`GithubAuthenticationController#callback` binds the authenticated GitHub identity to the current session as follows: [1](#0-0) 

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

No `reset_session` (or session-ID regeneration) is performed before `session[:user_id]` is assigned. Contrast with `logout`, which does call `reset_session`: [2](#0-1) 

The binding this breaks is: *the GitHub identity that completed OAuth* versus *the `User` that ends up bound to a given session cookie*. Because the session identifier is never rotated on login, an attacker who can pre-set (fixate) a victim's session cookie value before the victim authenticates can, after the victim logs in through GitHub, reuse that same fixed session ID to obtain an authenticated session bound to the victim's `User` record — without ever needing a Shipit session, an `ApiClient` token, or any GitHub credential of their own. `current_user` elsewhere in the engine trusts `session[:user_id]` unconditionally: [3](#0-2) 

### Impact Explanation
Session fixation on the OAuth completion endpoint allows an unprivileged external attacker to hijack an authenticated victim session after the victim completes login, effectively obtaining the victim's Shipit privileges (which can include deploy/rollback/merge rights depending on `Shipit.github_teams` membership) without ever needing the victim's or their own GitHub credentials, an `ApiClient` token, or prior repository access. This matches the explicitly listed High-severity impact: "session fixation / forced OAuth completion."

### Likelihood Explanation
Exploitability depends on the ability to plant a session cookie value in the victim's browser before they authenticate (e.g., via a shared subdomain, an open redirect, or a network position that lets an attacker set a cookie for the Shipit host) and then luring/forcing the victim to complete the GitHub OAuth login. This is a well-known, practical technique and requires no privileged credential, token, or prior access to the engine — matching the "unprivileged attacker" requirement. The engine does not mitigate it in any way, since `reset_session` is present only on `logout`, never on `callback`.

### Recommendation
Call `reset_session` (or otherwise rotate/regenerate the session identifier) in `GithubAuthenticationController#callback` immediately before or after setting `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout`.

### Proof of Concept
1. Attacker obtains/fixes a valid-looking session ID for the target Shipit host (e.g. by visiting the site unauthenticated and capturing the `_session_id` cookie value, or by forcing it onto the victim's browser via a cookie-setting mechanism available on a shared parent domain).
2. Attacker delivers this fixed session cookie to the victim (e.g., via a crafted link that sets the cookie, or by exploiting cookie scoping on a related subdomain) and induces the victim to log into Shipit via `/github/auth/github` → `/github/auth/github/callback`.
3. `callback` writes `session[:user_id] = victim_user.id` into the same session record identified by the fixed session ID, without rotating it.
4. Attacker replays the original (fixed) session cookie against the Shipit host and is now recognized by `current_user` as the victim, per `Shipit::Authentication#find_current_user`, gaining the victim's authorization level.

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

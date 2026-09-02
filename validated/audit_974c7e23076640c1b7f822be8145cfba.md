### Title
Session fixation on GitHub OAuth callback binds an attacker-fixed session to the victim's authenticated identity - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
The `GithubAuthenticationController#callback` action writes the newly authenticated `user_id` into the *existing* session without first calling `reset_session`, unlike `#logout`, which does. This breaks the trust binding that should hold between "the GitHub identity that completed OAuth" and "the session id that gets to act as that identity": any session id that existed *before* OAuth completion (including one an attacker planted in the victim's browser) becomes authenticated as the victim's `User` once the victim finishes the OAuth flow.

### Finding Description
`GithubAuthenticationController#callback` does:
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

Compare to `#logout`, which explicitly calls `reset_session`: [2](#0-1) 

Authorization for every subsequent request is then derived purely from `session[:user_id]`:
```ruby
def find_current_user
  session[:user_id].present? && User.find_by(id: session[:user_id])
end
``` [3](#0-2) 

The invariant that should hold is: `session_id -> GitHub identity that authenticated it` must be a fresh 1:1 binding established at login time. Instead, the binding is: `pre-existing session_id (attacker-controlled) == session_id post-login (victim's identity)`. Because the session cookie/id is never rotated on privilege escalation (unlike `reset_session` in `#logout`), an attacker who can fix a victim's session identifier (e.g. by planting a cookie via a subdomain, a network position that can set cookies, or any mechanism that lets them share/predict the pre-auth session id) can pre-establish a session, have the victim complete GitHub OAuth in that same session, and then reuse the identifier themselves to be treated as the victim by `current_user`/`find_current_user`.

This is the direct analog of the reported bug class: the report's binding was "the fee amount charged" vs. "the fee amount that should have been charged once" (two computations of the same value diverging because one path wasn't reset/cleared before the second ran). Here the analogous binding is "the session id before OAuth" vs. "the session id trusted after OAuth" — the session is never reset/rotated across the trust-elevation boundary, so a pre-boundary value (attacker's chosen session id) survives into the post-boundary trusted state.

### Impact Explanation
This is a **session fixation** finding, which the rules explicitly enumerate as a High-impact category ("session fixation / forced OAuth completion"). Successful exploitation lets an unprivileged external attacker hijack another user's authenticated Shipit session, gaining that user's authorization level (including any `Shipit.github_teams` membership enforced in `Authentication#force_github_authentication`) without needing the victim's GitHub credentials, a webhook secret, an API client token, or any other privileged material.

### Likelihood Explanation
Likelihood is Low/Medium: it requires the attacker to get a chosen session identifier into the victim's browser before the victim performs GitHub OAuth login (e.g., cookie-tossing across a shared/subdomain scope, or a network/host condition permitting a `Set-Cookie` for the session domain), and requires the victim to actually complete the OAuth flow in that session afterward. No cryptographic break, webhook secret, or repository write access is needed — only browser cookie-scope control and timing relative to a real login event.

### Recommendation
Call `reset_session` in `GithubAuthenticationController#callback` before assigning `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `#logout`:
```diff
 def callback
   return_url = request.env['omniauth.origin'] || root_path
   auth = request.env['omniauth.auth']
   return render('failed', layout: false) if auth.blank?

+  reset_session
   session[:user_id] = sign_in_github(auth)
   session[:authenticated] = true
   redirect_to(return_url)
 end
```
This rotates the session identifier at the authentication boundary, preventing any pre-authentication session id from being reused post-authentication.

### Proof of Concept
1. Attacker obtains/sets a specific session cookie value in the victim's browser for the Shipit host (e.g. via a cookie-scope weakness, or by simply sharing a link that causes the browser to adopt a session before login — any mechanism that plants a session id pre-auth).
2. Victim visits Shipit, is redirected to `/github/auth/github`, completes GitHub OAuth.
3. `GithubAuthenticationController#callback` runs `session[:user_id] = sign_in_github(auth)` on the **existing** (attacker-known) session rather than a freshly rotated one. [4](#0-3) 
4. Attacker, using the same session id/cookie, sends any authenticated request to Shipit; `find_current_user` resolves `session[:user_id]` to the victim's `User` record, and `force_github_authentication` grants access as the victim. [5](#0-4)

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-42)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end

    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

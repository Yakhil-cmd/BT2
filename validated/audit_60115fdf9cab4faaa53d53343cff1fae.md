### Title
Session fixation via missing `reset_session` in OAuth callback - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` writes `session[:user_id]` and `session[:authenticated]` into whatever session already exists for the incoming request, without ever calling `reset_session`. An attacker who can fix a victim's session id before the victim completes GitHub OAuth can hijack the resulting authenticated session.

### Finding Description
The binding that must hold is: `session.id` before OAuth == `session.id` after OAuth completes (i.e., the session id must be rotated on privilege change) so that an attacker-controlled session cookie cannot become an authenticated session. In the actual code, `callback` only mutates keys inside the existing session hash: [1](#0-0) 

There is no `reset_session` call anywhere in `callback` — the only place `reset_session` is invoked is in `logout` and in `force_github_authentication` when a stale login is detected: [2](#0-1) 

Attack flow: attacker obtains or plants a session cookie on the victim's browser (classic session-fixation delivery: shared kiosk, subdomain cookie scoping, or an attacker-initiated login link containing a known session id if the session store/id generation allows attacker-supplied ids to survive — many Rails cookie/redis session configurations will accept and persist any session id present in the cookie until the app explicitly rotates it). Victim then completes `Sign in with GitHub`; `callback` writes the victim's `user_id` into that same session id. Because the id was never rotated, the attacker — who already knows that session id/cookie — can now present it and be treated as the authenticated victim by `find_current_user`, which trusts `session[:user_id]` unconditionally: [3](#0-2) 

No existing guard prevents this: `force_github_authentication` only checks `current_user.logged_in?`/`requires_fresh_login?`/`authorized?`, none of which detect or block session-id reuse across a login transition. The existing test suite only asserts `session[:authenticated]` is true after callback, never asserting session-id rotation: [4](#0-3) 

### Impact Explanation
If an attacker can fix the session id on a victim's browser and the victim subsequently completes GitHub OAuth, the attacker gains full authentication as that victim's Shipit `User` — including access to any stacks/deploys/rollbacks the victim is authorized for and possibly `current_user.github_access_token` usage inside the app. This matches the "High - session fixation / forced OAuth completion" category listed in scope. It is repeatable for every login event as long as the attacker can re-fix the session id before each attempt, and it is not limited to a single repository — it grants full account takeover of whichever Shipit user completes login on the fixed session.

### Likelihood Explanation
Exploitability depends entirely on the precondition explicitly stated in scope: the attacker must be able to plant/fix a session id in the victim's cookie jar before the victim authenticates (e.g., shared/public machine, session id acceptance via a crafted `Set-Cookie` from a related subdomain, or any session store that does not always issue a new id per request). This is a standard external precondition for session-fixation classes of bugs and does not require any Shipit secret, GitHub secret, or privileged role — only cookie-jar control prior to the victim's login, which the question's threat model treats as available to the attacker. Given that precondition, the vulnerability triggers on every OAuth callback because `reset_session` is unconditionally absent from that code path.

### Recommendation
Call `reset_session` (or at minimum regenerate the session id, e.g. via `request.session_options[:renew] = true` / recreate the session) in `GithubAuthenticationController#callback` before writing `session[:user_id]`/`session[:authenticated]`, preserving `return_url` in a local variable first (since `reset_session` clears the session hash, including `omniauth.origin`-derived values already read into `return_url`). Concretely:

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
Minitest (integration test, not unit `ActionController::TestCase`, since session-id rotation cannot be observed through `ActionController::TestCase`'s session hash alone — an `ActionDispatch::IntegrationTest` with real cookie jar is required):

```ruby
require 'test_helper'

module Shipit
  class GithubAuthenticationSessionFixationTest < ActionDispatch::IntegrationTest
    test "callback rotates the session id on login (no fixation)" do
      # Step 1: attacker/victim shares a session cookie with an arbitrary pre-set value
      get shipit.root_path
      pre_login_session_cookie = cookies['_session_id'] # or app's session cookie name

      auth = OmniAuth::AuthHash.new(
        credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
        extra: OmniAuth::AuthHash.new(
          raw_info: OmniAuth::AuthHash.new(
            id: 44, name: 'Victim', email: 'victim@example.com',
            login: 'victim', avatar_url: 'https://example.com',
            api_url: 'https://github.com/api/v3/users/victim'
          )
        )
      )
      OmniAuth.config.mock_auth[:github] = auth
      Rails.application.env_config['omniauth.auth'] = auth

      get shipit.github_authentication_callback_path # /github/auth/github/callback
      post_login_session_cookie = cookies['_session_id']

      # Binding under test: session id before OAuth == session id after OAuth must be FALSE
      refute_equal pre_login_session_cookie, post_login_session_cookie,
        "Expected reset_session to rotate the session id on login, but it did not (session fixation)"
    end
  end
end
```

This test fixes/reads the session cookie before hitting the callback, then asserts the cookie's session id value changed after login. As shown, `callback` never calls `reset_session`, so this assertion currently fails, confirming the vulnerability.

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

**File:** app/controllers/concerns/shipit/authentication.rb (L20-24)
```ruby
    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
```

**File:** app/controllers/concerns/shipit/authentication.rb (L40-42)
```ruby
    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

**File:** test/controllers/github_authentication_controller_test.rb (L25-33)
```ruby
      assert_difference -> { User.count } do
        get :callback
      end

      user = User.find_by(login: 'shipit-user')
      assert_equal 's3cr3t', user.github_access_token
      assert_equal 44, user.github_id
      assert session[:authenticated], "Expected session[:authenticated] to be true"
    end
```

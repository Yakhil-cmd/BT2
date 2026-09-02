### Title
Session fixation on GitHub OAuth login due to missing `reset_session` - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` assigns `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` directly into the existing session hash without ever calling `reset_session`. Any pre-existing session state (and, on non-cookie session stores, the session identifier itself) survives the authentication transition, allowing a classic session-fixation attack against the victim's post-login session.

### Finding Description
The binding that should hold is: `session_id_before_login == session_id_after_login` must be **false** whenever the authenticated identity changes (i.e., a fresh session must be issued on privilege escalation). In `callback`, this binding is violated: [1](#0-0) 

The method reads `request.env['omniauth.auth']` and directly writes `session[:user_id]` and `session[:authenticated] = true` on the same session object that existed before the OAuth handshake began, with no call to `reset_session`. `logout` shows the engine is aware `reset_session` exists and is the correct primitive, since it's used there, but it's absent from `callback`.

Exploit flow: an attacker visits Shipit and obtains a valid (pre-authentication) session/cookie from the shared session store (e.g., an app configured with a server-side session store such as ActiveRecord/Redis session store, or any deployment where the session cookie/id can be planted into the victim's browser, e.g. via a shared parent domain). The attacker fixates that session into the victim's browser, then lures the victim to click the Shipit-issued OAuth login link. When the victim completes the OAuth handshake, `callback` writes the victim's authenticated `user_id` into the *same, attacker-controlled* session object rather than issuing a fresh one. If the attacker retains access to that same server-side session record/id, the attacker's browser is now also authenticated as the victim.

None of the existing guards mitigate this: `force_github_authentication`/`UserRequiredMiddleware` only gate whether a user must be logged in, not whether the session is regenerated on login; `verify_signature`/webhook checks are unrelated (this is a browser-session path, not webhook); there is no CSRF/state check on session identity in this controller beyond OmniAuth's own state param (which prevents forged auth callbacks, not fixation of the destination session).

### Impact Explanation
If exploitable in the host's deployment (i.e., session store where the identifier is fixable/shared), a successful attack lets the attacker's browser act as an authenticated victim in Shipit — able to trigger deploys, rollbacks, and access to all stacks the victim can access, which is full authentication bypass/session takeover scoped to whatever the victim's Shipit account is authorized to do. This matches the explicitly listed High-severity category "session fixation / forced OAuth completion."

### Likelihood Explanation
Exploitability is conditioned on the host application's session store configuration; Shipit's own `test/dummy` config is out of scope for this engine determination, and the engine itself does not restrict the host to a cookie-only store. Given the engine ships `logout` calling `reset_session` but `callback` does not, the omission is a real gap in the engine's own authentication code, independent of store, and is a well-established Rails anti-pattern (Rails security guides explicitly recommend `reset_session` on login for this exact reason). The attack requires only that the attacker can get the victim to load a page from Shipit's origin with a fixed session before finishing OAuth login (e.g., via a crafted link), and no Shipit or GitHub secrets are needed.

### Recommendation
Call `reset_session` at the start of `callback` (or immediately after obtaining `auth` and before assigning `session[:user_id]`), then re-set `session[:user_id]` and `session[:authenticated]` on the fresh session, mirroring the pattern already used in `logout`.

### Proof of Concept
Minitest (`ActionController::TestCase`/`ActionDispatch::IntegrationTest`) plan:
1. Start an integration session, hit any Shipit page to obtain a session cookie, and record a marker: `session[:pre_login_marker] = 'attacker-set'` (simulate fixation by writing to session before login, e.g., via a controller test that sets `session[:pre_login_marker]` directly on the pre-existing session, or by asserting the session cookie value is unchanged in identity terms).
2. Issue `GET /github/callback` with `@request.env['omniauth.auth']` mocked as in the existing test `test/controllers/github_authentication_controller_test.rb`.
3. Assert binding violation: `assert_equal 'attacker-set', session[:pre_login_marker]` (proves stale session data/session survives login) and `assert session[:user_id]` now equals the victim's `User#id`, i.e., the same session object now carries both the attacker-planted marker and the victim's identity — demonstrating `session_id_before_login == session_id_after_login` when it should not.
4. Assert no call to `reset_session` occurred by checking `session.id`/session hash identity is preserved end-to-end (unchanged from step 1 to step 3, aside from the newly added keys).

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

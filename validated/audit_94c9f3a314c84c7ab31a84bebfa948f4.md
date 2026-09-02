This confirms the finding: `GithubAuthenticationController#callback` never calls `reset_session` before writing `session[:user_id]`, unlike `logout` and `force_github_authentication` (which do call `reset_session` in the "fresh login" branch). This is a genuine session-fixation gap in this engine's own code.

### Title
Session fixation on OAuth login — session ID not rotated in `#callback` - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` sets `session[:user_id]` and `session[:authenticated]` directly from `request.env['omniauth.auth']` without ever calling `reset_session`. Contrast this with `#logout` and `force_github_authentication`'s "fresh login" branch, which do call `reset_session`. An attacker who fixes a victim's pre-authentication session ID (e.g., by setting the session cookie for the shared Shipit origin before the victim completes OAuth) can access the victim's authenticated Shipit account after the victim finishes login, because the underlying session ID is never rotated at the identity-binding boundary.

### Finding Description
The broken binding: `session_id_before_callback == session_id_after_callback` should be false (Rails convention: authentication must rotate the session ID), but in this code it is true.

Path: [1](#0-0)  — `#callback` reads `auth = request.env['omniauth.auth']`, then does `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` directly on the existing session, never calling `reset_session`. `sign_in_github` just creates/updates the `User` and returns its id: [2](#0-1) .

By contrast, `#logout` explicitly rotates the session via `reset_session`: [3](#0-2) , and `force_github_authentication`'s stale-login branch also calls `reset_session` before redirecting to re-authenticate: [4](#0-3) . This shows the codebase's own convention is to rotate sessions at trust-boundary transitions — `#callback` (the actual login boundary) is the one place that omits it.

`current_user` is derived purely from `session[:user_id]`: [5](#0-4) , so whichever session ID holds that key after `#callback` runs is fully equivalent to being logged in as that user for all subsequent requests.

Exploit flow: An attacker visits the Shipit host and obtains/sets a session cookie value (Shipit's session store is a standard Rails cookie/session store per `test/dummy/config/initializers/session_store.rb`). The attacker plants this same session identifier into the victim's browser (classic session-fixation delivery — e.g., a subdomain that can set cookies for the parent domain, or a login link with a forced session id if the store used is not purely cookie-based). The victim later visits Shipit, that fixed session already exists but is unauthenticated, and the victim completes GitHub OAuth. `#callback` writes `session[:user_id]` into that same, attacker-known session rather than issuing a fresh one. The attacker, still holding the original session identifier, now presents it and is treated as the victim by `current_user`/`force_github_authentication`.

No existing guard mitigates this: `force_github_authentication` only checks `current_user.logged_in?` and freshness, not session provenance [6](#0-5) ; there is no CSRF/state check visible in this controller beyond OmniAuth's own middleware, and nothing in `#callback` regenerates the session ID.

### Impact Explanation
Successful exploitation grants the attacker a fully authenticated Shipit session as the victim, without ever knowing the victim's GitHub credentials — i.e., authentication bypass via session fixation, matching the "High" impact category (session fixation / forced OAuth completion) and potentially escalating to "Critical" if the victim is a privileged Shipit maintainer, since the attacker could then trigger deploys, rollbacks, or merges as that user. This is repeatable against any victim who can be lured into completing OAuth on a session the attacker previously fixed, and it is not scoped to a particular repository/stack — it compromises the victim's entire Shipit identity.

### Likelihood Explanation
Preconditions: the attacker needs a way to fix/plant a session identifier into the victim's browser before the victim completes OAuth (a classic prerequisite of session-fixation attacks; feasibility depends on the deployed session store/cookie configuration, e.g., cookie scope, `SameSite`, and whether session IDs can be set cross-context). No Shipit secrets, tokens, or privileged roles are required from the attacker — only the ability to get a chosen session ID into the victim's browser and have the victim voluntarily complete GitHub login. This is a standard, well-known attack class (OWASP session fixation) and requires no interaction with GitHub secrets or Shipit internals beyond the missing `reset_session` call.

### Recommendation
Call `reset_session` at the start of `#callback` (after validating `auth` is present, before writing any session keys), then re-set `session[:user_id]` and `session[:authenticated]` on the freshly rotated session, mirroring the pattern already used in `#logout` and `force_github_authentication`.

### Proof of Concept
Minitest plan (integration test, no live GitHub):
1. In an `ActionDispatch::IntegrationTest`, perform a request to any Shipit path to establish an initial session, and capture the session cookie value / `session.id` before login (e.g., via `cookies['_session_id']` or `@request.session.id` in a controller test using `ActionController::TestCase` with `session` sharing enabled).
2. Stub `request.env['omniauth.auth']` with a valid `OmniAuth::AuthHash` (as in `test/controllers/github_authentication_controller_test.rb` lines 8-22) and issue `get :callback`.
3. Capture the session id/cookie after the callback response.
4. Assert `refute_equal session_id_before, session_id_after` — this assertion currently **fails** (they are equal) because `reset_session` is never called, proving the fixation.
5. Optionally assert `session[:user_id]` is present on the same (unrotated) session id, demonstrating that the pre-existing session now carries victim identity.

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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L20-34)
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
```

**File:** app/controllers/concerns/shipit/authentication.rb (L40-42)
```ruby
    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

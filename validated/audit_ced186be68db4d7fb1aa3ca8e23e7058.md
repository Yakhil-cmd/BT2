### Title
Session fixation in GitHub OAuth callback allows pre-authentication session hijacking - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` binds a freshly-authenticated GitHub identity to the *existing* Rack session without first rotating the session ID, unlike `#logout`, which explicitly calls `reset_session`. This breaks the intended binding: **the session identifier presented before authentication == the session identifier trusted after authentication**. An attacker who can plant/know a session identifier before a victim's OAuth exchange complete can hijack the victim's post-authentication, privileged session — the analog of the reported "commit-to-lien" flaw, where a value the caller doesn't control (the collateral holder / here, the true GitHub identity) is silently and unverifiedly bound to an action a third party requested (attaching an authenticated identity to an attacker-controlled session).

### Finding Description
`force_github_authentication` in `app/controllers/concerns/shipit/authentication.rb` derives `current_user` purely from `session[:user_id]`: [1](#0-0) 

The only two places that mutate `session[:user_id]`/session state are the callback and logout actions: [2](#0-1) [3](#0-2) 

`logout` calls `reset_session` (rotates the underlying session identifier and clears session data), but `callback` — the code path that runs immediately after a successful OAuth exchange and grants a session real privilege — does **not** call `reset_session` before writing `session[:user_id] = sign_in_github(auth)`. It merely reuses whatever session container the browser presented at the start of the flow: [4](#0-3) 

This is the same class of bug as the report: a downstream authorization decision (`current_user.logged_in?` / `authorized?`) is made by checking one field (`session[:user_id]`) against a party that never independently consented to *that specific session* being the one elevated to authenticated status. Just as the vault's `_validateCommitment` treated `receiver == holder` as sufficient proof of consent, Shipit's callback treats "a `user_id` now sits in *this* session" as sufficient proof that the browser holding this exact session is the one the user intended to authenticate — without rotating the session identifier to guarantee the pre-auth and post-auth sessions are the same trusted principal's browser.

### Impact Explanation
If an attacker can get a victim to browse the site under a session identifier known to or chosen by the attacker (e.g., a shared/predictable session-store key, a session-fixation vector via subdomain cookie scoping, or any mechanism that lets the attacker seed the victim's session before the OAuth round-trip completes — CSRF-triggering the login flow itself is even simpler since `callback` accepts both `GET` and `POST` per `config/routes.rb`), then once the victim completes GitHub OAuth, the *same* session the attacker seeded becomes authenticated as the victim. The attacker, holding that session, gains a fully authenticated `Shipit::User` session — able to trigger deploys, lock/unlock stacks, and otherwise act with the victim's `Shipit.github_teams` authorization, all without ever compromising GitHub credentials. This is an authentication-bypass class issue (session fixation / forced OAuth completion), matching the explicitly accepted High-impact category.

### Likelihood Explanation
Exploitability depends on the concrete session-store configuration (cookie-based signed sessions are harder to fixate than server-side stores keyed by a client-supplied identifier), which is host-application configuration and could not be fully verified from the engine code alone — `config/initializers/session_store.rb` exists only in `test/dummy` and is not authoritative for production deployments using this engine. Regardless of store, the missing `reset_session` in `callback` (present in `logout`) is a concrete deviation from safe-authentication practice within the engine's own code, and is the root cause that would need to be fixed to eliminate the fixation window; the routes also do not appear to enforce a nonce/state check inside the engine's own callback handler beyond what OmniAuth's middleware provides upstream.

### Recommendation
Call `reset_session` (and regenerate any CSRF token) in `GithubAuthenticationController#callback` before writing `session[:user_id]`, mirroring the treatment already given to `#logout`:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  auth = request.env['omniauth.auth']
  return render('failed', layout: false) if auth.blank?

  reset_session
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true

  redirect_to(return_url)
end
```

### Proof of Concept
Conceptual PoC (matches `test/controllers/github_authentication_controller_test.rb` fixtures):
1. Attacker obtains/plants a session identifier `S` in the victim's browser (e.g., via any mechanism that lets a session cookie be set cross-boundary before authentication, or by getting the victim to click a link that starts the OAuth flow using `S`).
2. Victim, using session `S`, completes the GitHub OAuth handshake; `GithubAuthenticationController#callback` runs and sets `session[:user_id] = victim.id` on session `S` without rotating it.
3. Attacker, who already knows/controls session identifier `S`, is now recognized by `Shipit::Authentication#current_user` as the victim for all subsequent requests, per: [5](#0-4) [6](#0-5)

### Citations

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

**File:** test/controllers/github_authentication_controller_test.rb (L7-33)
```ruby
    test ":callback can sign in to github" do
      auth = OmniAuth::AuthHash.new(
        credentials: OmniAuth::AuthHash.new(
          token: 's3cr3t'
        ),
        extra: OmniAuth::AuthHash.new(
          raw_info: OmniAuth::AuthHash.new(
            id: 44,
            name: 'Shipit User',
            email: 'shipit-user@example.com',
            login: 'shipit-user',
            avatar_url: 'https://example.com',
            api_url: 'https://github.com/api/v3/users/shipit-user'
          )
        )
      )
      @request.env['omniauth.auth'] = auth

      assert_difference -> { User.count } do
        get :callback
      end

      user = User.find_by(login: 'shipit-user')
      assert_equal 's3cr3t', user.github_access_token
      assert_equal 44, user.github_id
      assert session[:authenticated], "Expected session[:authenticated] to be true"
    end
```

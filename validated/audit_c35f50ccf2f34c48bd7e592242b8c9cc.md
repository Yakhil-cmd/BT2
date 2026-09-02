### Title
Session fixation via missing `reset_session` on GitHub OAuth login completion - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` binds a freshly authenticated GitHub identity to the *existing* session without first calling `reset_session`, so any session identifier established before the OAuth handshake remains valid and privileged after it. This breaks the equality that should hold: `session_id(pre-authentication) != session_id(post-authentication)`. An attacker who can plant/know a session identifier before a victim completes the OAuth flow inherits the victim's authenticated session.

### Finding Description
`callback` sets `session[:user_id]` and `session[:authenticated] = true` directly from the OmniAuth payload, with no `reset_session` call: [1](#0-0) 

Compare this to `logout`, which explicitly calls `reset_session`: [2](#0-1) 

and to `Authentication#force_github_authentication`, which resets the session only in the narrow "stale/fresh login required" case, not on the normal login path: [3](#0-2) 

The binding that should hold is: the session identifier used to authorize subsequent requests must be regenerated at the moment the session's privilege level changes (anonymous → authenticated `User`). Because `sign_in_github` only mutates `session[:user_id]` inside the pre-existing session object, whichever party controls that session identifier before the OAuth callback controls it afterward too — i.e. the "GitHub identity that authenticated" and the "`User` bound to the session" are decoupled from the actual holder of the session token.

`current_user` in `Authentication` trusts `session[:user_id]` unconditionally to resolve the acting `User`: [4](#0-3) 

so once `session[:user_id]` is set for a fixated session, every subsequent authorization check (`current_user.authorized?`, team membership checks, deploy triggers, etc.) treats the holder of that pre-existing session token as the victim.

### Impact Explanation
This maps to the "session fixation / forced OAuth completion" High-impact category explicitly called out in scope: an attacker who fixates a session identifier and then induces a victim to complete the GitHub OAuth login in that same session ends up holding a live, fully authenticated session as the victim — including whatever `Shipit.github_teams` authorization and deploy/rollback/merge privileges the victim's GitHub identity grants. This is an authentication-boundary violation: the session's privilege changes from anonymous to a specific `User`, but the identifier that grants access to that session state is never rotated.

### Likelihood Explanation
Exploitability depends on the application's session storage mechanism (cookie-based vs. server-side store id) and on the ability to fix a session identifier in the victim's browser before they complete the OAuth flow. This is a real code-level gap (no `reset_session` on login) independent of any privileged credential, ApiClient token, webhook secret, or GitHub App key — matching the "unprivileged attacker" constraint. However, I was unable to verify from the indexed files whether the host application's `config/initializers/session_store.rb` (outside `app/**`/`lib/shipit/**`, and only present in the test dummy app in this repo) configures a server-side session store where a session id can be pre-set by an attacker, or the Rails default `ActionDispatch::Session::CookieStore`, where the entire session payload is embedded in a signed/encrypted cookie rather than referenced by a guessable id. This detail materially affects how directly exploitable classic session fixation is, and it is a host-application configuration concern outside this engine's own code, so likelihood should be treated as uncertain pending that configuration.

### Recommendation
Call `reset_session` (or otherwise regenerate the session id) in `GithubAuthenticationController#callback` immediately before assigning `session[:user_id]`/`session[:authenticated]`, mirroring the pattern already used in `logout` and in the stale-login branch of `force_github_authentication`:

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
1. Attacker obtains/plants a session identifier for the target Shipit instance in the victim's browser (mechanism depends on the deployed session store; e.g. via a link that sets the session cookie in a shared-store deployment).
2. Attacker sends the victim a link starting the GitHub OAuth flow (`/github/auth/github`) while the victim's browser still carries the attacker-known session.
3. Victim authenticates with GitHub; `GithubAuthenticationController#callback` runs and sets `session[:user_id] = sign_in_github(auth)` on the *same* session object, without calling `reset_session`.
4. Attacker, using the previously known session identifier, now has an authenticated session as the victim, inheriting `current_user`, `Shipit.github_teams` authorization, and the ability to trigger deploys/rollbacks/merges as the victim. [1](#0-0) [4](#0-3)

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

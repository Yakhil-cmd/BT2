### Title
Session fixation on GitHub OAuth callback: authenticated session bound to a pre-existing session ID without regeneration - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` establishes an authenticated Shipit session (`session[:user_id]`, `session[:authenticated]`) after a successful GitHub OAuth handshake, but it never regenerates/resets the session prior to writing these keys. Any session identifier that existed in the browser *before* OAuth completion (e.g. planted by an attacker) is kept and silently "upgraded" to an authenticated session once the victim finishes the OAuth flow, exactly mirroring the reported bug class: state is written/merged into pre-existing storage without first clearing/accounting for what was already there.

### Finding Description
The binding that should hold is: *the session identifier that receives the authenticated `User` binding == a session identifier that was created as part of, or immediately after, this specific authentication event*. Instead, the equality that actually holds is: *the session identifier that receives the authenticated binding == whatever session identifier already existed in the cookie jar when the browser hit `/github/auth/github/callback`*.

`callback` does this: [1](#0-0) 

Note that `session[:user_id] = sign_in_github(auth)` and `session[:authenticated] = true` are plain writes into the *existing* `session` object for the current request/cookie — there is no `reset_session` call, unlike the `logout` action which does call it: [2](#0-1) 

`Authentication#force_github_authentication` also only calls `reset_session` in the narrow "requires fresh login" branch, not on normal login completion: [3](#0-2) 

Because Rails' cookie/session identifier is not rotated at the moment of privilege escalation (anonymous → authenticated `User`), the write is analogous to the Tessera bug: a value (`session[:user_id]`) is unconditionally set into a container (the session hash tied to a specific session id) whose pre-existing state (the session id itself, and anything an attacker seeded into it before the victim authenticated) is not invalidated first. The "collateral" in the Tessera analogy is the authenticated identity; the "pendingBalance" container is the session id — instead of guaranteeing the container is fresh (the `+=`-safe equivalent would be regenerating the session id), Shipit keeps writing into whatever container is already there (the `=` overwrite equivalent).

### Impact Explanation
If an attacker can fix a session identifier in a victim's browser before the victim completes GitHub OAuth login (classic session-fixation delivery: e.g. planting a cookie via a subdomain, a response-splitting bug, or simply sharing a pre-authenticated login link/URL that contains a session cookie set by the attacker), the attacker's session cookie becomes bound to the victim's authenticated `Shipit::User` once the victim finishes the OAuth dance at `/github/auth/github/callback`. The attacker, holding the same session id, would then be treated by `Authentication#current_user`/`find_current_user` as the logged-in victim: [4](#0-3) 

This is explicitly listed as an accepted High-severity impact category ("session fixation / forced OAuth completion"), since it lets an unprivileged attacker escalate into the victim's authenticated identity and therefore into whatever `Shipit.github_teams` authorization and stack/deploy permissions that user has, without needing an API token, webhook secret, or GitHub App key.

### Likelihood Explanation
Exploitation requires the attacker to be able to fix a session id in the victim's browser and get the victim to complete the OAuth flow while that session id is active — this is a standard, well known technique (not requiring the app's GitHub credentials, a Shipit API token, or a webhook secret), and the code path is unconditionally reachable by any visitor to the OAuth callback endpoint. The missing `reset_session` at the successful-login boundary is a concrete code defect independent of any other misconfiguration.

### Recommendation
Call `reset_session` (or otherwise regenerate the session id) in `GithubAuthenticationController#callback` immediately before or after writing `session[:user_id]`/`session[:authenticated]`, so that a freshly-authenticated session never reuses a pre-existing session identifier.

### Proof of Concept
1. Attacker obtains/fixes a session cookie value `S` for the target Shipit host (e.g., by visiting the site first and copying the `Set-Cookie` value, or via any mechanism that lets them plant a chosen session id in the victim's browser for that domain).
2. Attacker delivers a link to the victim that causes the victim's browser to carry session cookie `S` and initiates `/github/auth/github/callback` completion (the OAuth `state`/`code` exchange itself is between victim and GitHub, but the resulting session write still lands in cookie `S` because `callback` never resets it — see `app/controllers/shipit/github_authentication_controller.rb:7-21`).
3. Victim completes the real GitHub OAuth login using session `S`. `sign_in_github` resolves/creates the victim's `User` and `session[:user_id]` is set on session `S` without any `reset_session` call.
4. Attacker, still holding session cookie `S`, sends subsequent requests to Shipit; `Authentication#find_current_user` (`app/controllers/concerns/shipit/authentication.rb:40-42`) resolves `current_user` to the victim, giving the attacker the victim's authenticated privileges (team authorization, deploy permissions, etc.) without ever knowing the victim's GitHub credentials.

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

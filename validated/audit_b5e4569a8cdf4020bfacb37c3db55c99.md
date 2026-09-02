### Title
Session Fixation via GitHub OAuth Callback Not Rotating Session on Privilege Elevation - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
The bug class in the reference finding is a missing early-exit / missing state-reset branch for a boundary condition (`hedgeDelta(0)`), which leaves stale, unintended state in place instead of cleanly resetting it. The analogous class of bug in this engine is `GithubAuthenticationController#callback` binding a newly-authenticated GitHub identity (`User`) to whatever session the browser presented, without first invalidating/rotating that session — i.e. it never resets pre-authentication session state before elevating it, exactly the "do nothing / reset" branch that is missing.

### Finding Description
`GithubAuthenticationController#callback` receives the OmniAuth GitHub auth payload and writes the resulting `User#id` directly into the *existing* session: [1](#0-0) 

Note it never calls `reset_session` before assigning `session[:user_id]`. Compare this to two other places in the same authentication surface that *do* correctly call `reset_session` when transitioning session privilege:
- `logout` calls `reset_session` before redirecting. [2](#0-1) 
- `force_github_authentication` calls `reset_session` when a stale/legacy token is detected, before forcing re-login. [3](#0-2) 

The equality that should hold is: *the session identifier/state that existed before GitHub identity verification* must not equal *the session identifier/state after the `User` is bound to it* — i.e., authentication must issue a fresh session. Instead, `callback` preserves the pre-auth session and merely mutates its `user_id` key, so:

`session_before_oauth == session_after_oauth` (same session container, only `user_id` mutated)

This is the same shape of defect as `hedgeDelta(0)`: a state-transition entry point (`callback`, analogous to `hedgeDelta`) that should perform a clean reset of prior state before establishing the new (authenticated) state, but instead reuses/extends the old state, leaving attacker-influenced material (a pre-seeded session) intact through the privilege transition.

`current_user`/`find_current_user` then trust `session[:user_id]` unconditionally for all subsequent requests engine-wide (stacks, tasks, api_clients, repositories, deploys): [4](#0-3) 

### Impact Explanation
If an attacker can get a victim to authenticate (complete the GitHub OAuth flow) while using a session container the attacker already controls/knows (a classic session-fixation precondition, e.g. a shared/attacker-influenced session cookie), the attacker's browser will subsequently be recognized as the same authenticated `User` because `session[:user_id]` was written into the pre-existing session rather than a freshly rotated one. This is a session fixation / forced OAuth completion issue, matching the High-impact bullet for this engine ("session fixation / forced OAuth completion"). Once fixated, the attacker inherits the victim's `current_user`, including access to all stacks, deploys, rollbacks, task triggering, and `ApiClient` management the victim is authorized for — effectively an authentication-bypass-by-proxy for that account.

### Likelihood Explanation
Exploitability depends entirely on the deployer's session store configuration; this repository's engine code does not pin a session store (that's left to the host Rails app), so whether a session identifier is fixable (server-side store) or not (encrypted cookie store, which is the common Rails default) varies by deployment. Regardless of store type, the code-level defect — omitting a session reset at the exact point of privilege elevation — is present and is the root cause; it is a genuine control-flow gap analogous to the missing "do nothing" branch in `hedgeDelta(0)`, independent of whether a given deployment's session backend makes it trivially exploitable.

### Recommendation
Call `reset_session` (or otherwise regenerate the session identifier) in `GithubAuthenticationController#callback` immediately before assigning `session[:user_id]`, mirroring the pattern already used in `logout` and in `force_github_authentication`'s stale-token branch, so that no session created prior to GitHub identity verification survives the transition to an authenticated session.

### Proof of Concept
Conceptual PoC (session-fixation precondition assumed, e.g. server-side/session-id-based store):
1. Attacker visits the Shipit instance unauthenticated, obtaining a session cookie/session id `S`.
2. Attacker causes `S` to be planted in the victim's browser (e.g., via a shared kiosk, a subdomain that can set the cookie, or any mechanism that lets the attacker fix the session identifier the victim will use).
3. Victim, using session `S`, navigates to `/github/auth/github` and completes the GitHub OAuth flow.
4. `GithubAuthenticationController#callback` executes: [5](#0-4) 
   writing the victim's `user_id` into session `S` without rotating it.
5. Attacker, who already possesses session `S`, now sends requests using that same session and is treated as the victim by `current_user`/`find_current_user`: [4](#0-3) 
6. Attacker now has full access to every engine surface (`stacks`, `deploys`, `tasks`, `api_clients`, etc.) as the victim, without ever knowing the victim's GitHub credentials.

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

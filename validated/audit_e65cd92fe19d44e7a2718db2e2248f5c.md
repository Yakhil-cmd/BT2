### Title
Unvalidated `omniauth.origin` used in post-login `redirect_to` enables open redirect - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` reads `request.env['omniauth.origin']` and passes it directly to `redirect_to` after establishing the authenticated session, with no check that the URL is scoped to `Shipit.host` or is a same-host path. Since OmniAuth's default `callback_phase` behavior copies whatever value was supplied via the `origin` query parameter on the initial `GET /github/auth/github?origin=...` request into `session['omniauth.origin']` and later exposes it as `request.env['omniauth.origin']` on callback, an attacker can craft a login link that redirects a victim to an attacker-controlled site immediately after the victim's Shipit session cookie is set.

### Finding Description
Binding claimed broken: `request.env['omniauth.origin'] == URL scoped to Shipit.host`.

Trace:
- `config/routes.rb` mounts `GET /github/auth/github` (`action: :request`), `GET/POST /github/auth/github/callback` (`callback`). [1](#0-0) 
- OmniAuth (mounted via the engine's Rack middleware, see `lib/shipit/engine.rb`) intercepts the `/github/auth/github` request phase and stores `params['origin']` into `session['omniauth.origin']` (standard OmniAuth behavior). On callback it restores that value into `request.env['omniauth.origin']`.
- `GithubAuthenticationController#callback` does:
```
return_url = request.env['omniauth.origin'] || root_path
...
redirect_to(return_url)
``` [2](#0-1) 
There is no check that `return_url` starts with `/` (a relative path) or matches `Shipit.host`/`request.host`. The `force_github_authentication` before_action (the internal caller of this flow) only ever sets `origin` to `request.original_url` (same host) when redirecting unauthenticated users to log in, [3](#0-2)  but nothing prevents an attacker from directly hitting the OmniAuth request-phase URL themselves with an arbitrary `origin` query parameter, bypassing that internal call site entirely.

Attacker's request: send/trick a victim into visiting
`GET https://shipit.example.com/github/auth/github?origin=https://evil.example.com`
The victim completes the real GitHub OAuth handshake (this part is legitimate — no forgery of GitHub identity is required), Shipit sets `session[:user_id]`/`session[:authenticated] = true` (their genuine, freshly authenticated session), and then `redirect_to(return_url)` sends their browser to `https://evil.example.com`.

None of the listed guards (`verify_signature`, `require_permission!`, `User#authorized?`, model validators, `ExplicitParameters`) apply here — they guard API/webhook/authorization paths, not the OmniAuth callback's redirect target. `force_github_authentication` and `User#authorized?` run on subsequent requests but do not retroactively validate this redirect.

### Impact Explanation
The attacker gains an open redirect from a trusted, authenticated Shipit URL, executed right after the victim's session cookie is set. This can be leveraged for phishing (victim believes they are still interacting with a trusted post-login flow, landing on attacker's page), or forced navigation attacks. It does not by itself leak `github_access_token` or Shipit secrets — no token or secret is appended to `return_url` by Shipit's own code, so the "Critical credential exfiltration" combination described in the question is not demonstrated in this engine. The direct, demonstrable impact is an open redirect immediately following authentication, matching the High-severity bucket for session-adjacent issues (forced navigation after OAuth completion). It is repeatable against any victim who clicks a crafted link; it does not escalate privileges or mutate any stack/repository data.

### Likelihood Explanation
Preconditions: attacker needs no Shipit session, no secrets, and no special repository access — only the ability to get a URL opened by a victim's browser (standard phishing-link distribution), which is within the stated attacker capability ("any internet user who can send HTTP requests to the Shipit host"). No special Shipit or GitHub configuration is required beyond the default GitHub OAuth login flow being enabled. Cost is minimal and the technique is fully repeatable.

### Recommendation
In `Shipit::GithubAuthenticationController#callback`, validate `return_url` before redirecting: only allow relative paths (e.g., `return_url.start_with?('/') && !return_url.start_with?('//')`) or explicitly check the URL's host matches `Shipit.host`/`request.host`; otherwise fall back to `root_path`.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback redirects to attacker-controlled origin (open redirect)" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Shipit User', email: 'x@example.com',
      login: 'shipit-user', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/shipit-user'
    ))
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://evil.example.com'

  get :callback

  # Binding under test:
  # left  = request.env['omniauth.origin']          => "https://evil.example.com"
  # right = URL scoped to Shipit.host                => should equal left, but doesn't
  assert session[:authenticated], "victim session was authenticated"
  assert_not_equal URI(response.redirect_url).host, Shipit.host,
    "callback redirected authenticated victim off-host, to: #{response.redirect_url}"
  assert_redirected_to 'https://evil.example.com' # demonstrates the open redirect
end
```
This confirms that after a real, successful authentication (`session[:authenticated]` true), the controller redirects to a host different from `Shipit.host`, proving `return_url` is never validated against the app's own host.

### Citations

**File:** config/routes.rb (L70-75)
```ruby
  scope '/github/auth/github', as: :github_authentication, controller: :github_authentication do
    get '/', action: :request
    post :callback
    get :callback
    get :logout
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

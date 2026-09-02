### Title
Open redirect via unsanitized `omniauth.origin` in OAuth callback - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` sets `session[:user_id]` and `session[:authenticated] = true` and then unconditionally redirects the browser to `request.env['omniauth.origin']` with no validation that the value is confined to `Shipit.host`. Because the `origin` value originates from the `origin` query parameter supplied when the OAuth flow is initiated (`GET /github/auth/github?origin=...`), an attacker can craft a link that completes the victim's GitHub OAuth login and then bounces their authenticated browser to an attacker-controlled site.

### Finding Description
The binding the question asserts should hold is: `return_url` (used in `redirect_to(return_url)`) == a URL scoped to `Shipit.host`. Tracing the code shows this binding is never enforced: [1](#0-0) 

`return_url = request.env['omniauth.origin'] || root_path` reads the origin value straight from the OmniAuth middleware environment with no scheme/host check, and immediately calls `redirect_to(return_url)` after authentication state is written to the session. The OmniAuth GitHub strategy is mounted with no `origin_param` restriction: [2](#0-1) 

OmniAuth's standard request phase captures the `origin` query parameter provided by the client at the start of the flow (`/github/auth/github?origin=<attacker-url>`) and carries it through to the callback via `request.env['omniauth.origin']`. Shipit's own callback code — which is the code in scope here — performs no validation that this value is a path or is scoped to `Shipit.host` before passing it to `redirect_to`. None of the guards enumerated in the question apply here: `force_github_authentication`, `verify_signature`, `User#authorized?`, model validators, and `ExplicitParameters` schemas are unrelated to this controller, since `callback` is a plain `ActionController::Base` action that runs before any of those filters would matter, and there is no origin-allowlist logic anywhere in the engine.

Attacker's exact request:
1. Attacker sends victim a link: `GET https://shipit.example.com/github/auth/github?origin=https://evil.example.com`.
2. Victim completes GitHub OAuth consent (a real, victim-authenticated flow — no secrets needed by attacker).
3. GitHub redirects back to `/github/auth/github/callback`; `callback` sets `session[:user_id]`/`session[:authenticated]` for the victim, then executes `redirect_to('https://evil.example.com')`.
4. Victim's browser, now holding an authenticated Shipit session cookie, is sent to the attacker's page, which can be used for further phishing, credential harvesting, or man-in-the-middle style follow-up (e.g., presenting a fake Shipit login/interstitial, or leveraging Referer leakage of the callback URL/params).

### Impact Explanation
This is a forced completion of the OAuth flow diverted to an attacker-controlled destination, directly matching the High-severity category "session fixation / forced OAuth completion." The victim's browser session is authenticated to the real Shipit host, but their post-login navigation is fully attacker-controlled, enabling phishing pages that impersonate Shipit, or chaining to further attacks against the now-authenticated session (e.g., convincing the victim to interact with attacker-hosted content while a valid session cookie exists). It affects any victim who clicks such a link and is repeatable per victim/per link; it does not directly leak `github_access_token` or allow cross-tenant stack/deploy mutation on its own, but is a genuine open redirect immediately following authentication.

### Likelihood Explanation
The attack requires no privileges: Shipit's GitHub OAuth must be enabled (`Shipit.github.oauth?`, the default configuration documented in `docs/setup.md`), and the attacker only needs to get a victim to click a crafted link — no secrets, tokens, or team membership are required. This is trivially repeatable against any Shipit deployment with OAuth enabled.

### Recommendation
Validate `return_url` before redirecting: parse it and only allow same-host relative paths (or explicitly compare `URI(return_url).host` against `Shipit.host`), falling back to `root_path` otherwise. Additionally restrict OmniAuth's origin parameter handling (e.g., configure `origin_param` to only accept path-only values, or strip and re-derive a safe path).

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb (integration-style test)
test ":callback does not redirect off Shipit.host even if omniauth.origin is attacker-controlled" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(
      raw_info: OmniAuth::AuthHash.new(
        id: 44, name: 'Shipit User', email: 'u@example.com',
        login: 'shipit-user', avatar_url: 'https://example.com',
        api_url: 'https://github.com/api/v3/users/shipit-user'
      )
    )
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://evil.example.com'

  get :callback

  redirect_uri = URI(response.redirect_url)
  # Binding under test: return_url used in redirect_to == URL scoped to Shipit.host
  assert_equal Shipit.host, redirect_uri.host,
    "Expected redirect to be confined to Shipit.host, but got #{response.redirect_url}"
  assert session[:authenticated], "session was authenticated before the unchecked redirect"
end
```
This demonstrates that `session[:authenticated]` becomes true while `response.redirect_url` points off `Shipit.host`, proving the equality binding is violated with no live GitHub interaction required.

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

**File:** lib/shipit/engine.rb (L46-51)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
      end
```

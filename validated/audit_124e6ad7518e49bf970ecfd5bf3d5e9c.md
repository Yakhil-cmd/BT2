### Title
Open redirect in `Shipit::GithubAuthenticationController#callback` via unvalidated `omniauth.origin` - (File: `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
`GithubAuthenticationController#callback` sets `return_url = request.env['omniauth.origin'] || root_path` and, after successfully authenticating the user and writing `session[:user_id]`/`session[:authenticated]`, calls `redirect_to(return_url)` with no host allow-list check. Since OmniAuth's default `origin` handling stores the `origin` request parameter verbatim in `request.env['omniauth.origin']`, an attacker can craft a link that sends a victim's freshly-authenticated browser to an attacker-controlled URL immediately after completing real GitHub OAuth.

### Finding Description
The broken binding: `return_url` (the redirect target) should be constrained to `return_url ∈ {URLs under Shipit.host}`, but instead `return_url == request.env['omniauth.origin']`, which is attacker-controlled input carried through from the `origin` query parameter of the initial `/github/auth/github` request.

Code path: [1](#0-0) 

`callback` reads `omniauth.origin` (line 8), performs sign-in (line 13), sets `session[:authenticated] = true` (line 18), then redirects unconditionally to that value (line 20) with no scheme/host validation, no `url_for`/`only_path` restriction, and no comparison against `Shipit.host` or `root_path`.

Attacker request: a link like `GET /github/auth/github?origin=https://evil.example` sent to a victim who is a legitimate Shipit operator with valid GitHub credentials. OmniAuth's request phase captures `origin` and stores it in `omniauth.origin`, which the strategy re-injects into `env` on the callback phase. The victim completes the real GitHub OAuth handshake (this part cannot be forged by the attacker — genuine GitHub auth is required), and upon return, `callback` redirects the victim's browser, now holding a valid, freshly-set `_shipit_session` cookie, to `https://evil.example`.

No existing guard (`force_github_authentication`, `verify_signature`, `UserRequiredMiddleware`, or the routes config in `lib/shipit/engine.rb`) validates `return_url`; the engine's OmniAuth setup only configures the strategy path prefix and provider credentials, not `origin` sanitisation.

### Impact Explanation
Per request, an attacker gets the ability to redirect an authenticated operator's browser anywhere they choose immediately following legitimate OAuth completion. This is an open redirect at minimum. This alone does **not** leak the `_shipit_session` cookie itself to `evil.example` (cookies aren't automatically included cross-domain in the redirect Location header, and the session cookie flags — `HttpOnly`/`SameSite`/`Secure`, as configured by `Shipit::SameSiteCookieMiddleware` or Rails session store defaults — are not overridden by this controller). What it does directly enable is: phishing (a convincing "reauthenticate" page on the attacker's domain right after a real GitHub login, which could trick a victim into pasting credentials/API tokens), or chaining with an XSS/other bug elsewhere. Without a demonstrated mechanism by which this redirect alone exfiltrates the session cookie or `github_access_token`, this does not meet the "Critical" bar (credential/token exfiltration or auth bypass) claimed in the question; it aligns at best with the "High" category as an open redirect adjacent to the OAuth flow, but does not on its own achieve "forced OAuth completion" or session fixation (the attacker cannot force or select which GitHub account authenticates, nor read `session[:user_id]`).

### Likelihood Explanation
Preconditions are cheap: this requires `Shipit.github.oauth?` to be enabled (standard OAuth login config) and the attacker only needs to get a victim operator to click a link — no privileged Shipit role, no secrets, and no interaction with webhooks or repositories is needed. This is realistically low-cost and repeatable against any Shipit deployment using GitHub OAuth login.

### Recommendation
Validate `return_url` before redirecting: only allow relative paths (e.g., using `url.start_with?('/')` and rejecting `//` protocol-relative URLs) or explicitly check the parsed host equals `Shipit.host`/`request.host`, falling back to `root_path` for anything else.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback redirects to attacker-controlled origin (open redirect)" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(
      raw_info: OmniAuth::AuthHash.new(
        id: 44, name: 'Shipit User', email: 'shipit-user@example.com',
        login: 'shipit-user', avatar_url: 'https://example.com',
        api_url: 'https://github.com/api/v3/users/shipit-user'
      )
    )
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://evil.example'

  get :callback

  assert_redirected_to 'https://evil.example'
  assert session[:authenticated]
end
```
This demonstrates `return_url == request.env['omniauth.origin']` (attacker value) rather than `return_url ∈ {Shipit.host paths}`, confirming the unvalidated redirect. Note: I could not find any sanitisation of `omniauth.origin` elsewhere in the engine (`lib/shipit/engine.rb`, `app/controllers/concerns/shipit/authentication.rb`), so this appears to be a genuine, currently-unmitigated open redirect, though its severity is best characterized as High (open redirect / phishing vector tied to OAuth), not Critical credential exfiltration, absent an additional demonstrated cookie-leak mechanism.

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

### Title
Unvalidated `omniauth.origin` used in post-login `redirect_to` enables open-redirect after legitimate OAuth completion - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` builds `return_url` directly from `request.env['omniauth.origin']` with no host/path validation and passes it straight into `redirect_to(return_url)` after a successful OAuth sign-in. An attacker can craft a link that starts the OAuth flow with an external `origin`, causing the victim's browser to be redirected to an attacker-controlled URL immediately after authenticating, while the Shipit session cookie has already been set with `SameSite=None` by `SameSiteCookieMiddleware`.

### Finding Description
The intended binding is: `return_url` derived from `omniauth.origin` must equal `Shipit.host` (or be a same-host relative path) — never an arbitrary external URL. The actual code is: [1](#0-0) 

`return_url = request.env['omniauth.origin'] || root_path` takes the OmniAuth `origin` value verbatim (this is typically populated from the `origin` query parameter on the initial `/github/auth/github` request path by the OmniAuth middleware) and feeds it unmodified into `redirect_to(return_url)`. There is no check against `Shipit.host`, no `only_path` constraint, and no allowlist. The only test coverage for this controller (`test/controllers/github_authentication_controller_test.rb`) exercises `omniauth.auth` but never sets or asserts anything about `omniauth.origin`, so this path is untested.

No repo-level Rails configuration (`config.action_controller.raise_on_open_redirects` / `allow_other_host`) was found that would cause `redirect_to` to reject cross-host URLs, so nothing in the surrounding Rails config mitigates this at the framework level.

Exploit flow: an unauthenticated attacker sends a victim a link such as `/github/auth/github?origin=https://attacker.example/steal`. The victim, who already trusts/uses Shipit, completes the real GitHub OAuth handshake. On the `callback` action, `sign_in_github` succeeds, `session[:user_id]` and `session[:authenticated]` are set on the victim's browser, and then the browser is redirected to `https://attacker.example/steal`. Combined with `SameSiteCookieMiddleware` forcing `SameSite=None` on all cookies over HTTPS, the victim's Shipit session cookie becomes eligible to be sent on subsequent cross-site requests, and the redirect chain gives the attacker a forced navigation immediately following authentication — a classic open-redirect/forced-navigation pattern following a real login.

Existing guards (`force_github_authentication`, `User#authorized?`, `require_permission!`, webhook signature checks) are irrelevant here since this is a pre-authorization controller reachable by any unauthenticated GitHub user completing a legitimate OAuth flow; none of them constrain `return_url`.

### Impact Explanation
This maps to the High-severity category "session fixation / forced OAuth completion": the attacker forces a legitimate OAuth completion and controls the post-login redirect destination to an attacker-controlled URL. It does not directly exfiltrate `github_access_token` (that value stays server-side), but it enables phishing continuations (e.g., an attacker page mimicking Shipit to harvest further credentials) and, combined with `SameSite=None` cookies, increases exposure of the session cookie to subsequent cross-site request flows. This is repeatable against any victim who clicks the crafted OAuth link; it does not cross tenant/repository boundaries by itself but affects the individual victim account being signed in.

### Likelihood Explanation
No special Shipit or repository configuration is required beyond the engine being mounted with GitHub OAuth (the default). The attacker's cost is a single crafted link; the victim must click it and complete the real GitHub OAuth prompt (which most users would do without suspicion, since the GitHub auth screen itself is legitimate). No secrets are needed by the attacker. This is easily repeatable per victim.

### Recommendation
Validate `return_url` before redirecting: only allow it if it is a relative path (`return_url.start_with?('/')` and not `//`) or matches `Shipit.host`; otherwise fall back to `root_path`. Alternatively, use `redirect_to(return_url, allow_other_host: false)` (Rails 7+) or enable `config.action_controller.raise_on_open_redirects = true` engine/host-app-wide, and add regression tests asserting redirects to non-Shipit origins are rejected.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback rejects external omniauth.origin" do
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
  @request.env['omniauth.origin'] = 'https://attacker.example/steal'

  get :callback

  # Binding under test: redirect target host must equal Shipit.host / root_path,
  # never the attacker-controlled origin.
  refute_equal 'https://attacker.example/steal', @response.redirect_url
  assert_equal root_path, @response.redirect_url
end
```
Running this against current code fails: `@response.redirect_url` equals `https://attacker.example/steal`, confirming the unvalidated open redirect.

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

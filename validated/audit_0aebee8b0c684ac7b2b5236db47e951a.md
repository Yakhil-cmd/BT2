### Title
Unvalidated `omniauth.origin` causes open redirect / forced-OAuth-completion after login - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` uses `request.env['omniauth.origin']` directly as the post-login redirect target without validating that it points to a path on the Shipit host. Since OmniAuth's request phase (`/github/auth/github?origin=...`) stores the client-supplied `origin` parameter verbatim for later use at the callback step, an attacker can craft a login link that, once the victim completes real GitHub OAuth, redirects the now-authenticated browser to an attacker-controlled absolute URL.

### Finding Description
**Binding claimed to be broken:** `return_url == same-origin path within Shipit` should always hold before `redirect_to(return_url)` executes; instead the code allows `return_url == request.env['omniauth.origin']` unconditionally.

Code path: [1](#0-0) 

`return_url` is computed solely from `request.env['omniauth.origin'] || root_path` with no check that it is a relative path or that it resolves to the Shipit host [2](#0-1) . `omniauth.origin` is populated by the OmniAuth gem's request phase from the `origin` query/form parameter supplied by the client at `/github/auth/github`, and is carried through the OAuth dance (via session or state) to be read again at `/github/auth/github/callback`. Nothing in this controller, or in the surrounding engine code inspected (`sign_in_github`, `logout`), sanitizes or restricts this value to same-origin paths.

Attacker flow:
1. Attacker sends victim a link: `GET /github/auth/github?origin=https://attacker.example`.
2. Victim completes real GitHub OAuth (their own legitimate credentials — no secrets needed).
3. `callback` fires, sets `session[:user_id]`/`session[:authenticated]`, then executes `redirect_to(return_url)` where `return_url == "https://attacker.example"` [3](#0-2) .
4. Victim's browser, now holding a valid authenticated Shipit session cookie, is sent to the attacker's page.

No existing guard applies here: `force_github_authentication`, `require_permission!`, and CSRF token protection govern *other* controllers (deploy/task actions), not this redirect target; this controller does not filter the origin at all. The existing test suite only asserts sign-in behavior and never exercises or restricts the redirect target [4](#0-3) , confirming the missing scoping check.

### Impact Explanation
The direct, demonstrable impact is an open redirect that forces the victim's browser to land on an attacker-controlled page immediately after a genuine authentication event ("forced OAuth completion"), which matches the High-severity category of session fixation / forced OAuth completion. The session cookie itself is not exfiltrated to the attacker (it remains scoped to the Shipit host), so this alone does not directly hand the attacker a valid session or CSRF-execute a deploy — the further chaining to "an unauthorized deploy" asserted in the question requires a separate, unverified CSRF vulnerability on a deploy-triggering endpoint (state-changing Shipit actions require an authenticity token, which an external attacker page cannot forge, and this was not found broken in the code reviewed). Absent evidence that a deploy/rollback/merge endpoint accepts unauthenticated-CSRF-token requests, the escalation to "unauthorized deploy" is speculative and not demonstrated in this engine's own code.

### Likelihood Explanation
Preconditions are minimal: the attacker needs no Shipit credentials, no GitHub App secrets, and no privileged role — only the ability to send the victim a crafted link and have them complete a normal GitHub login, which is highly feasible via phishing. The redirect itself is trivially repeatable against any victim and any target URL.

### Recommendation
Validate `return_url` before redirecting: reject absolute URLs or URLs whose host does not match the Shipit application's own host (e.g., require `URI.parse(return_url).relative?` or compare `URI.parse(return_url).host` against the request host), falling back to `root_path` otherwise.

### Proof of Concept
```ruby
test ":callback does not redirect to external origin" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Shipit User', email: 'x@example.com',
      login: 'shipit-user', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/shipit-user'
    ))
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://attacker.example'

  get :callback

  # Broken binding demonstrated: assert_equal 'https://attacker.example', response.location
  # Expected/fixed behavior:
  assert_no_match(%r{\Ahttps?://attacker\.example}, response.location)
end
```
Running this against current code shows `response.location == 'https://attacker.example'`, proving `return_url` is unscoped to the Shipit host.

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

**File:** test/controllers/github_authentication_controller_test.rb (L5-34)
```ruby
module Shipit
  class GithubAuthenticationControllerTest < ActionController::TestCase
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
  end
```

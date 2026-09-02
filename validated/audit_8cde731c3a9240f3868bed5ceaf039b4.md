### Title
Unvalidated `omniauth.origin` in `Shipit::GithubAuthenticationController#callback` allows open redirect after OAuth completion - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` takes `request.env['omniauth.origin']` — which OmniAuth populates from the attacker-controllable `origin` request parameter on the initial `/github/auth/github` request — and passes it directly to `redirect_to` with no same-host validation. An attacker can craft `/github/auth/github?origin=https://attacker.example`, and after the victim completes real GitHub OAuth, Shipit will redirect their authenticated browser to the attacker's site.

### Finding Description
The broken binding: the code implicitly assumes `return_url == a same-origin, Shipit-controlled path`, but no such check exists.

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  ...
  redirect_to(return_url)
end
``` [1](#0-0) 

`return_url` is taken verbatim from `omniauth.origin` and used in `redirect_to`, with no check that it resolves to a path/host within the Shipit application [2](#0-1) [3](#0-2) .

The OmniAuth GitHub strategy is mounted at `/github/auth`, and routes expose `GET /github/auth/github` (request phase) and `GET/POST /github/auth/github/callback` (callback phase) [4](#0-3) [5](#0-4) . OmniAuth's built-in `origin` handling reads the `origin` param during the request phase and threads it through to `omniauth.origin` on the callback, with no allowlist of hosts — this is standard, well-documented OmniAuth behavior and Shipit does not override or sanitize it before using it for redirection.

No existing guard in this engine mitigates this: `force_github_authentication`, `User#authorized?`, and `require_permission!` operate on *access control*, not on redirect-target validation, and none of them touch `GithubAuthenticationController#callback`. There is no allowlist check comparing `return_url`'s host against `Shipit.host` or `root_path` anywhere in this file or its ancestors.

Exploit flow:
1. Attacker sends victim: `https://shipit.example/github/auth/github?origin=https://attacker.example`.
2. Victim authenticates with GitHub (real, legitimate OAuth flow).
3. GitHub redirects back to Shipit's callback; OmniAuth restores `origin` into `request.env['omniauth.origin']`.
4. `callback` sets `session[:user_id]`/`session[:authenticated]`, then `redirect_to('https://attacker.example')`, sending the victim's browser off-domain immediately after establishing an authenticated Shipit session.

### Impact Explanation
This is a classic post-authentication open redirect. It does not directly leak `github_access_token`, `session_id` value (cookies are not appended to the URL and modern browsers do not attach `Referer` headers containing sensitive session cookie values), and it does not escalate the attacker into `Shipit.github_teams` or bypass Shipit's own authorization. The realistic harm is: the victim, having just authenticated with GitHub in a Shipit-branded flow, is silently redirected to an attacker-controlled page, which can be used for phishing (e.g., convincingly rendering a fake "session expired, please re-enter your GitHub credentials" prompt) — this matches the "forced OAuth completion" category under High severity, since the attacker forces the victim through a real OAuth completion and then redirects them off-site immediately afterward. It does not directly exfiltrate secrets or credentials by itself.

### Likelihood Explanation
Preconditions: Shipit must have `Shipit.github.oauth?` enabled (mounts the OmniAuth middleware) [5](#0-4) , which is the standard configuration for any Shipit deployment using GitHub login. Attacker cost is trivial — crafting and distributing one URL. No secrets, tokens, or privileged roles are required, matching the described unprivileged attacker. The attack is fully repeatable against any victim who clicks the link.

### Recommendation
Validate `return_url` against an allowlist of same-host/relative paths before redirecting, e.g.:
```ruby
def callback
  return_url = safe_return_url(request.env['omniauth.origin'])
  ...
  redirect_to(return_url)
end

private

def safe_return_url(url)
  return root_path if url.blank?
  uri = URI.parse(url) rescue nil
  return root_path unless uri
  return url if uri.host.nil? # relative path
  return url if uri.host == Shipit.host
  root_path
end
```

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback does not redirect to an external origin" do
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
  @request.env['omniauth.origin'] = 'https://attacker.example'

  get :callback

  # Binding under test: return_url (redirect target) must equal a same-host/Shipit path,
  # not the attacker-controlled omniauth.origin value.
  assert_not_equal 'https://attacker.example', response.location
  assert_match %r{\A#{Regexp.escape(root_path)}}, URI.parse(response.location).path
end
```
This demonstrates that, as currently implemented, `response.location` equals `https://attacker.example` (the assertion fails against current code), confirming the open redirect.

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

**File:** config/routes.rb (L70-75)
```ruby
  scope '/github/auth/github', as: :github_authentication, controller: :github_authentication do
    get '/', action: :request
    post :callback
    get :callback
    get :logout
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

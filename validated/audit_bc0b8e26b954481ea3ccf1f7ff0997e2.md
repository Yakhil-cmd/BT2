### Title
Unvalidated `omniauth.origin` causes open redirect after successful GitHub OAuth login - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` redirects the browser to `request.env['omniauth.origin']` with no host allow-list check, and this origin value is attacker-controllable through the `origin` query parameter on the unauthenticated `/github/auth/github` route. An attacker can force a victim to complete a legitimate GitHub OAuth login on Shipit and then be redirected to an attacker-controlled URL immediately after authentication succeeds.

### Finding Description
The broken binding is: `request.env['omniauth.origin'] == a URL under Shipit's own host`, which the code never enforces.

Path: `config/routes.rb` maps `scope '/github/auth/github' ... get '/', action: :request` [1](#0-0) . The OmniAuth GitHub strategy is mounted at that same path prefix via `OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')` [2](#0-1) . OmniAuth's standard behavior is to read the `origin` request parameter (or Referer) on the initial request phase and stash it into `request.env['omniauth.origin']`, which is preserved through the OAuth round trip and made available on the callback. Shipit's own code does not add any validation on top of this.

`Shipit::Authentication#force_github_authentication` itself does not introduce the vulnerability directly — it only redirects unauthenticated users to `github_authentication_path(origin: request.original_url)`, which is Shipit's own URL [3](#0-2) . The exploitable sink is `GithubAuthenticationController#callback`:
```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  ...
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [4](#0-3) 

Attacker request: send victim a link to `GET /github/auth/github?origin=https://attacker.example`. Victim, unauthenticated, is taken through the real GitHub OAuth consent screen using their own credentials, so no GitHub secret is needed. On success, `callback` sets `session[:user_id]`/`session[:authenticated]` for the victim (correct, legitimate login) then executes `redirect_to('https://attacker.example')`, sending the freshly authenticated browser off-host.

No existing guard prevents this: `force_github_authentication` is unrelated to the callback flow, there is no `verify_signature` equivalent for this endpoint (it's not a webhook), and no allow-list/`same-origin?` check exists on `return_url` anywhere in this controller.

### Impact Explanation
Per request, the attacker achieves an open redirect immediately following a genuine, victim-authenticated Shipit login — this is a forced-OAuth-completion / redirect primitive that can be used for phishing (landing the victim on an attacker page right after a trusted GitHub consent screen) and to funnel victims toward credential-harvesting pages under the guise of the Shipit login flow. This matches the "session fixation / forced OAuth completion" High-severity category. It does not, however, cause the `github_access_token` itself to leave the server (it is stored server-side only, never rendered to the client), and Shipit's session cookie is set via `Set-Cookie` on the same response and is not itself transmitted to `attacker.example` by the browser (Referer would only include the URL, not the cookie, assuming default cookie handling). The repeatable, demonstrable part of the impact is the open redirect + forced completion of a real login into attacker-controlled UI, not direct token exfiltration.

### Likelihood Explanation
Attacker cost is minimal: crafting and sending a single URL with an `origin` query parameter. No Shipit secrets, GitHub App credentials, or privileged roles are required — this is reachable by any unauthenticated internet user able to get a victim to click a link, exactly as described in the attacker model. It is repeatable against any victim and does not depend on stack/repository configuration.

### Recommendation
Validate `return_url` against an allow-list of same-host paths before redirecting in `GithubAuthenticationController#callback`, e.g. only allow relative paths (reject absolute URLs / protocol-relative URLs) or explicitly check `URI.parse(return_url).host` against `Shipit.host`, falling back to `root_path` otherwise.

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

  assert session[:authenticated], "victim session should be authenticated"
  assert_redirected_to 'https://evil.example'
end
```
This demonstrates the equality `request.env['omniauth.origin'] == Shipit's own host` does not hold (it is `https://evil.example`), yet `redirect_to(return_url)` is still executed at [5](#0-4) , proving the missing allow-list.

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

**File:** lib/shipit/engine.rb (L46-51)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
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

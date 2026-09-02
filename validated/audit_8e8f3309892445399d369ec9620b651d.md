### Title
Unvalidated `omniauth.origin` allows open redirect after forced GitHub OAuth login - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` takes `request.env['omniauth.origin']` — which is populated from the attacker-controllable `origin` query parameter on the `/github/auth/github` OAuth-initiation route — and passes it unvalidated into `redirect_to` after establishing the session. An attacker can craft a link that forces a victim through GitHub login and then redirects the now-authenticated browser to an arbitrary external host.

### Finding Description
The broken binding is: `return_url` (used in `redirect_to(return_url)`) should equal "a same-host, application-relative path", but instead `return_url = request.env['omniauth.origin'] || root_path` can equal any attacker-supplied absolute URL. [1](#0-0) 

The engine's own code passes `origin: request.original_url` when redirecting unauthenticated users to the OAuth start route: [2](#0-1) 

But `omniauth-github`/`omniauth-oauth2` (via the base `OmniAuth::Strategy`) reads the `origin` query parameter directly from the incoming request during the request phase and stores it in the session, later exposing it to the callback as `env['omniauth.origin']`. There is no code in this engine (no initializer, no before_action, no host-matching check) that restricts this value to Shipit's own host — `grep` for `origin_param`, `OmniAuth::Builder`, or any origin-validation logic in `config/`, `lib/shipit/engine.rb`, and the controllers turned up nothing that constrains it.

Exploit flow:
1. Attacker sends victim a link: `https://shipit.host/github/auth/github?origin=https://attacker.example/phish`
2. Victim (an unauthenticated or session-expired Shipit operator) clicks it, is sent to GitHub OAuth, authenticates legitimately with their own GitHub account.
3. GitHub redirects back to `/github/auth/github/callback`. The controller sets `session[:user_id]` and `session[:authenticated] = true` — the victim is now logged in to Shipit.
4. `redirect_to(return_url)` sends the victim's browser to `https://attacker.example/phish`, which can capture query fragments, mimic the Shipit UI for follow-on phishing, or chain with other referer/token leaks.

None of the existing guards (`force_github_authentication`, `User#authorized?`, CSRF protections) address this because they operate on inbound requests, not on the redirect target chosen after a successful, legitimate OAuth handshake. The vulnerability is a pure open-redirect / forced-OAuth-completion issue, not an authentication bypass — the attacker never forges a session for themselves, but they do force the victim to complete a real login and then hijack the post-login navigation.

### Impact Explanation
The attacker cannot steal `session[:user_id]` or any Shipit-side secret directly from this endpoint. The concrete impact is forcing a victim's browser, immediately after establishing an authenticated Shipit session, to land on an attacker-controlled origin — enabling phishing (fake re-login pages harvesting GitHub/Shipit credentials), or chaining with other open-redirect-driven attacks (e.g., leaking `Referer` headers containing internal Shipit URLs/tokens to the attacker's server). This matches the "session fixation / forced OAuth completion" High-severity category. It is repeatable against any operator who can be lured to click the crafted link; it does not require a Shipit session, API token, or GitHub team membership.

### Likelihood Explanation
Preconditions are minimal: the attacker needs only to get a Shipit operator (or anyone permitted to attempt login) to click a link of the form `/github/auth/github?origin=<attacker-url>`. No Shipit secrets, GitHub App credentials, or privileged roles are required. This is a standard link-based social engineering vector but requires no code execution, no MITM, and no compromised dependency — just a crafted URL, matching the allowed attacker capabilities.

### Recommendation
Validate `return_url` before redirecting: parse it and confirm it is a relative path (no scheme/host) or that its host matches `request.host`/`Shipit.host`; otherwise fall back to `root_path`. E.g., in `callback`, reject any `omniauth.origin` value where `URI.parse(return_url).host` is present and differs from the current request host.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb (proof, not to be merged)
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
  @request.env['omniauth.origin'] = 'https://attacker.example/phish'

  get :callback

  assert session[:authenticated], "victim session got authenticated"
  assert_redirected_to 'https://attacker.example/phish' # demonstrates unrestricted external redirect
end
```
This shows `return_url` (`https://attacker.example/phish`) diverges from "same-host relative path" while the victim's session is nonetheless authenticated, confirming the broken binding.

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

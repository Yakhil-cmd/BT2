### Title
Unvalidated `origin` param in OAuth callback enables open redirect / forced OAuth completion - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`Shipit::GithubAuthenticationController#callback` takes `return_url` directly from `request.env['omniauth.origin']` — which is populated from the attacker-controllable `origin` query parameter sent to the `/github/auth/github` request phase — and passes it unvalidated into `redirect_to(return_url)` right after setting `session[:user_id]` and `session[:authenticated] = true`. There is no check that `return_url` is a path scoped to `Shipit::Engine.routes` or even to the Shipit host.

### Finding Description
The intended binding is: `return_url` (the value passed to `redirect_to` after successful OAuth) **must resolve to a path inside `Shipit::Engine.routes`, i.e. a path on the Shipit host**. In the code: [1](#0-0) 

`return_url = request.env['omniauth.origin'] || root_path` is used verbatim in `redirect_to(return_url)` with no scheme/host allow-list, no `Shipit::Engine.routes.recognize_path` check, and no `allow_other_host: false` guard. The `origin` value that seeds `omniauth.origin` originates from the `origin` query parameter that Shipit itself appends when forcing login: [2](#0-1) 

but an attacker doesn't need to go through that code path — they can construct their own link directly to `/github/auth/github?origin=//attacker.example` (or any absolute URL) and send it to a victim. OmniAuth's default `origin_param` reads `params['origin']` verbatim at the request phase, stores it (session or state param), and replays it into `env['omniauth.origin']` at the callback phase — with no format/host validation performed by this engine's controller. `force_github_authentication` and `verify_signature`/webhook checks are irrelevant here since this is a browser-facing OAuth flow, not a webhook or API-token path, so none of those guards apply.

Exploit flow:
1. Attacker sends victim a link: `GET /github/auth/github?origin=//attacker.example`.
2. Victim completes real GitHub OAuth (Shipit correctly verifies the OAuth exchange).
3. `callback` sets `session[:user_id]`/`session[:authenticated]` (victim is now logged into the real Shipit host) and then does `redirect_to(return_url)` with `return_url == "//attacker.example"`.
4. Depending on the app's Rails configuration for `raise_on_open_redirects`/`allow_other_host`, the browser is redirected off-host to the attacker's page immediately after a real, valid Shipit login — enabling phishing, e.g., an attacker page presenting a fake re-login or fake application state that appears to originate from a just-completed legitimate session.

### Impact Explanation
No secret, token, or session cookie is disclosed by this bug directly, but the victim's browser is redirected off the Shipit host right after successful authentication, breaking the expectation that the post-login destination stays inside the engine. This enables phishing / forced OAuth completion: an attacker can stage a convincing follow-up page (e.g., re-prompting credentials or presenting a fake action) immediately after the victim's legitimate Shipit login, which can be leveraged toward session or credential-harvesting attacks. This matches the "session fixation / forced OAuth completion" High-severity category. It affects any victim who clicks the crafted link, is not scoped to a particular repository or stack, and is repeatable per victim/target.

### Likelihood Explanation
The precondition is minimal: OAuth authentication must be enabled (`Shipit.github.oauth?`), which is the default deployment mode for the engine. The attacker needs no Shipit credentials, no repository access, and no privileged role — only the ability to send the victim a URL, which matches the "unprivileged internet user" threat model in scope. The actual impact (whether the browser will follow an absolute/scheme-relative redirect) depends on the host application's Rails version and `config.action_controller.raise_on_open_redirects` setting, which is not verifiable from this engine's own code (this configuration lives in the host app, and `Gemfile.lock`/`Gemfile*` are out of scope for this audit). Because the engine performs zero validation of its own regardless of that framework-level setting, the engine itself is missing defense-in-depth, but full exploitability is conditional on the host's Rails redirect-safety configuration, which I could not confirm within this repo (out-of-scope files).

### Recommendation
In `Shipit::GithubAuthenticationController#callback`, validate `return_url` before redirecting: restrict it to same-host paths only, e.g. reject absolute/scheme-relative URLs and require the value to resolve via `Shipit::Engine.routes.recognize_path` (or `Rails.application.routes.recognize_path`), falling back to `root_path` otherwise. Alternatively, explicitly pass `redirect_to(return_url, allow_other_host: false)` (Rails ≥ 7) and ensure `return_url` is derived only from a whitelisted set of known internal paths rather than the raw `origin` param.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback rejects off-host origin redirect" do
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
  @request.env['omniauth.origin'] = '//attacker.example'

  get :callback

  # Binding under test: redirect Location host must equal Shipit host, not attacker.example
  refute_match(%r{\Ahttps?://attacker\.example}, response.location.to_s)
  refute response.location.to_s.start_with?('//attacker.example')
  assert_redirected_to root_path # or another in-engine path
end
```
This currently fails because `callback` redirects to `//attacker.example` unmodified.

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

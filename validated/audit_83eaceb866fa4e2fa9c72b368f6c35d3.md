### Title
Unvalidated `omniauth.origin` used as post-login redirect target enables open redirect after authentication - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` takes `request.env['omniauth.origin']` and passes it directly to `redirect_to` without validating that it points back to the Shipit host. Because the `origin` query parameter that seeds `omniauth.origin` is attacker-controllable on the OAuth-initiation request, an attacker can craft a login link that authenticates the victim's browser to Shipit and then bounces it to an arbitrary external URL.

### Finding Description
The broken binding is: `return_url` (used in `redirect_to(return_url)`) should always equal a URL within the Shipit host's own route set, but the code allows `return_url == request.env['omniauth.origin']`, an externally supplied value, with no allow-list check. [1](#0-0) 

The engine only ever *generates* the origin link safely, via `Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url)` in `force_github_authentication`: [2](#0-1) 

However, that safe usage does not prevent an attacker from directly constructing their own link to `GET /github/auth/github?origin=https://evil.example` and sending it to a victim/operator. OmniAuth's underlying strategy round-trips the `origin` request parameter unchanged into the session and later exposes it as `env['omniauth.origin']` at the callback phase, with no host/path validation performed by OmniAuth itself. Because `github_authentication_controller.rb` also performs no validation before calling `redirect_to(return_url)`, the value flows straight through to the browser's `Location` header after `session[:user_id]` and `session[:authenticated] = true` have already been set on the legitimate Shipit domain.

None of the existing guards address this: `force_github_authentication` only decides whether to redirect *to* the login flow, not what happens *after* successful login; `User#authorized?` and `Shipit.github_teams` checks happen on subsequent authenticated requests, not on the redirect target itself; there is no `ExplicitParameters` schema or webhook signature check involved here since this is a session-based browser flow, not an API/webhook path.

### Impact Explanation
This produces a post-authentication open redirect: the victim's browser ends up authenticated to Shipit (cookie set) but is sent to an attacker-chosen external host, which can be used for phishing, credential harvesting look-alike pages, or chaining with other browser-based leaks. It does not itself expose `github_access_token`, `api_clients_secret`, or grant `Shipit.github_teams` membership, and does not let the attacker act as another user or mutate stack/task/deploy state directly — it is limited to controlling the final `Location` after login completes. This aligns with the "session fixation / forced OAuth completion"-adjacent High-severity bucket describing forced completion of an OAuth flow toward attacker infrastructure, though actual credential exfiltration would require an additional mechanism (e.g., a browser leaking secrets via referrer), which is speculative here.

### Likelihood Explanation
Exploitation only requires an unauthenticated attacker to send a link (e.g., `https://shipit.example/github/auth/github?origin=https://evil.example`) to an operator and have them click it and complete the normal GitHub OAuth login — no secrets, tokens, or privileged roles are needed. This matches the attacker model (unprivileged internet user, no Shipit session). The main uncertainty is the exact version/configuration of the `omniauth` and `omniauth-github` gems mounted by the host app, which determines precisely how `origin` param becomes `omniauth.origin`; this behavior lives in the OmniAuth gem, not in this engine's own code, so the deficiency is that this engine's `callback` fails to add its own validation on top, not that OmniAuth itself is broken.

### Recommendation
In `Shipit::GithubAuthenticationController#callback`, validate that `return_url` is a same-host relative path (e.g., only accept it if `URI.parse(return_url).host.blank?` or if it matches a specific route/prefix), falling back to `root_path` otherwise, before calling `redirect_to`.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback redirects only to local URLs even if omniauth.origin is external" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Shipit User', email: 'shipit-user@example.com',
      login: 'shipit-user', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/shipit-user'
    ))
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://evil.example/steal'

  get :callback

  assert session[:authenticated]
  refute_match(/\Ahttps?:\/\/evil\.example/, response.redirect_url,
    "return_url should never redirect off the Shipit host")
end
```
Currently this assertion fails because `response.redirect_url` equals `https://evil.example/steal`, confirming the open redirect.

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

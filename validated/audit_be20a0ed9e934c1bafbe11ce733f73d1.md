### Title
Unvalidated `origin` param causes open redirect after OAuth callback - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`GithubAuthenticationController#callback` builds `return_url` directly from `request.env['omniauth.origin']` and passes it unmodified to `redirect_to`, with no check that it stays within `Shipit.host`. Since OmniAuth's request phase mirrors the `origin` query parameter into `omniauth.origin` (round-tripped via session/state until the callback), an attacker can craft a link that forces a victim who completes login to be redirected off the Shipit host.

### Finding Description
The binding that should hold is: `redirect_to(return_url)` target's host == `Shipit.host` (the value initialized in `lib/shipit/engine.rb:21-22` and used to scope the whole app), for every value the app will honor as a post-login destination.

Code path:
- `app/controllers/shipit/github_authentication_controller.rb:8`: `return_url = request.env['omniauth.origin'] || root_path`
- `app/controllers/shipit/github_authentication_controller.rb:20`: `redirect_to(return_url)`
- The `origin` value that seeds `omniauth.origin` originates from the `origin` query parameter passed to the OAuth request endpoint, as evidenced by `force_github_authentication` building the auth link with `origin: request.original_url` (`app/controllers/concerns/shipit/authentication.rb:24,32`) and by the existing test asserting the redirect target `'/github/auth/github?origin=...'` (`test/controllers/api_clients_controller_test.rb:16`).
- No code in this engine (controller, concern, or `lib/shipit/engine.rb`) validates that `return_url`/`origin` resolves to a URL on `Shipit.host` before it is stored/reflected and eventually passed to `redirect_to`.

Exploit flow: an attacker sends a victim a link such as `https://<shipit-host>/github/auth/github?origin=https://evil.example/phish`. The victim, who is not yet authenticated (or whose session is reset via `force_github_authentication`), is sent through the normal GitHub OAuth flow. OmniAuth preserves the `origin` param across the request/callback round trip. When GitHub redirects back to `.../callback`, `request.env['omniauth.origin']` contains the attacker-supplied `https://evil.example/phish`, and the controller redirects the now-authenticated victim's browser there via `redirect_to(return_url)` (`app/controllers/shipit/github_authentication_controller.rb:20`).

None of the codebase's existing guards address this: `force_github_authentication` (`app/controllers/concerns/shipit/authentication.rb`) only checks whether the user is logged in/authorized, it does not validate the `origin` value; there is no `require_permission!`, `verify_signature`, or URL/host validator anywhere in the OAuth callback path.

### Impact Explanation
A victim who clicks the crafted link and completes a legitimate GitHub login is redirected, at the end of the flow, to an attacker-controlled destination while still holding an authenticated Shipit session cookie on the Shipit host. This is a forced-completion-of-OAuth / open-redirect primitive: the attacker cannot steal the session cookie directly (it's `httponly`/scoped to the Shipit host), but they can chain this into further phishing (e.g., presenting a convincing fake page right after a real login, or redirecting to a URL that carries a follow-on token/action if the host app or another surface embeds sensitive query data in `origin`). This matches the "High - session fixation / forced OAuth completion" impact category from the rubric. It is repeatable against any victim who clicks such a link and is not scoped to a particular repository/stack — it's account/session-level, not tenant-data-level.

### Likelihood Explanation
No special Shipit configuration or secrets are needed. The attacker only needs to get a target user (who has a legitimate GitHub account eligible to log in to this Shipit instance) to click a link with a malicious `origin` parameter, which is a low-cost, standard phishing setup. The vulnerability is fully attacker-triggerable without any privileged role, matching the "unprivileged internet user" threat model in scope.

### Recommendation
Validate `return_url` before redirecting: parse it and require it be a relative path or have a host matching `Shipit.host`, e.g.:
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
  return url if uri.host == URI.parse("http://#{Shipit.host}").host
  root_path
end
```
Alternatively rely on Rails' `redirect_to(..., allow_other_host: false)` semantics (ensuring `config.action_controller.raise_on_open_redirects` is enabled in the host app) as defense in depth, but the primary fix belongs in this engine since the vulnerable value originates and is consumed here.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback does not redirect to an attacker-controlled origin" do
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
  @request.env['omniauth.origin'] = 'https://evil.example/phish'

  get :callback

  redirect_uri = URI.parse(@response.location)
  assert_not_equal 'evil.example', redirect_uri.host,
    "Expected redirect target host to equal Shipit.host (#{Shipit.host}), got attacker-controlled host instead"
end
```
This asserts the equality `redirect target host == Shipit.host` fails today (the test would currently show `@response.location == 'https://evil.example/phish'`), confirming the vulnerability. [1](#0-0) [2](#0-1) [3](#0-2)

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

**File:** lib/shipit/engine.rb (L20-22)
```ruby
    initializer 'shipit.config' do |app|
      Rails.application.routes.default_url_options[:host] = Shipit.host
      Shipit::Engine.routes.default_url_options[:host] = Shipit.host
```

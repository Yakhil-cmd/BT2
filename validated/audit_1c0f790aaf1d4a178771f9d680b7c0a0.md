### Title
Open Redirect via Unvalidated `omniauth.origin` in `GithubAuthenticationController#callback` - (File: app/controllers/shipit/github_authentication_controller.rb)

### Summary
`Shipit::GithubAuthenticationController#callback` builds the post-login redirect target directly from `request.env['omniauth.origin']` with no host/scheme validation before calling `redirect_to`. Since OmniAuth's request phase persists the `origin` query parameter supplied by whoever initiates `/github/auth/github`, an attacker can craft a login link that causes a legitimately-authenticating victim to be redirected to an attacker-controlled external URL immediately after a successful, real GitHub OAuth exchange.

### Finding Description
The broken binding: the redirect host after `callback` should satisfy `URI(return_url).host == request.host` (i.e., same-origin as the Shipit engine), but the code only enforces `return_url = request.env['omniauth.origin'] || root_path` [1](#0-0) , with no comparison against `Shipit.host` or `request.host` at all — any string OmniAuth stashes in `omniauth.origin` is passed straight into `redirect_to`.

Internally, the only place this engine itself constructs an `origin` value is `force_github_authentication`, which always uses `request.original_url` (same-host) when redirecting unauthenticated users to the auth path: `redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))` [2](#0-1) . However, nothing in this engine's routes or controller stops an external caller from hitting `GET /github/auth/github?origin=https://attacker.example` directly and supplying an arbitrary value for the `origin` param themselves — that request never passes through `force_github_authentication`'s same-host construction because it's the initiating GET, not a redirect from this app. OmniAuth's own request-phase middleware (outside this engine, but exercised by it) reads that `origin` param and persists it, later exposing it back to `callback` via `request.env['omniauth.origin']`, and this controller trusts it unconditionally.

Exploit flow:
1. Attacker sends victim `GET /github/auth/github?origin=https://attacker.example`.
2. Victim completes a real GitHub OAuth authorization (attacker does not need any secret — the victim does the actual login).
3. `callback` fires, sets `session[:user_id]`/`session[:authenticated] = true`, then executes `redirect_to(request.env['omniauth.origin'])`, sending the now-authenticated victim's browser to `https://attacker.example`.

No existing guard intercepts this: `force_github_authentication` only runs on subsequent authenticated requests within the engine and is not invoked by `GithubAuthenticationController` (auth is skipped for this controller), `verify_signature`/`GitHubApp#verify_webhook_signature` are unrelated to browser auth flow, and there is no allow-list or same-host check anywhere in `callback`.

### Impact Explanation
Per-request, the attacker obtains a valid, freshly-authenticated Shipit session redirect to an external URL of their choosing, immediately after the victim proves ownership of GitHub credentials. This is not a credential/token leak by itself (no `github_access_token` or `session` cookie value is disclosed to the attacker's page via URL), but it does allow staging further attacks: phishing a subsequent re-authentication, or chaining with other same-site request flows immediately after a trusted OAuth completion. This is repeatable against any victim who clicks the crafted link and is not scoped to a specific stack/repository — it is a control-plane (login flow) issue rather than a per-tenant data issue.

### Likelihood Explanation
Attacker cost is minimal: crafting and distributing one URL (`/github/auth/github?origin=https://attacker.example`) requires no Shipit credentials, no repository access, and no knowledge of secrets. The only precondition is a victim who is willing to click a Shipit-hosted link and complete a real OAuth login — a scenario the question explicitly allows. This is fully repeatable and requires no special Shipit or GitHub configuration beyond the default engine mount.

### Recommendation
Validate `return_url` against the app's own host before redirecting, e.g.:
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
  return root_path unless uri && (uri.host.nil? || uri.host == request.host)
  url
rescue URI::InvalidURIError
  root_path
end
```
Alternatively, restrict to relative paths only (reject any URL containing `://` or starting with `//`).

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback must not redirect to an external origin" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Shipit User', email: 'shipit-user@example.com',
      login: 'shipit-user', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/shipit-user'
    ))
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://attacker.example'

  get :callback

  redirect_host = URI.parse(@response.location).host
  assert_equal @request.host, redirect_host, "controller redirected to external host #{@response.location}"
end
```
Current code fails this assertion because `redirect_host` will be `attacker.example`, demonstrating the equality `URI(return_url).host == request.host` does not hold.

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

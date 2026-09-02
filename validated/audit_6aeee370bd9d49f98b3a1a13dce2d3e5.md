### Title
Open Redirect via unvalidated `omniauth.origin` in `GithubAuthenticationController#callback` - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`GithubAuthenticationController#callback` takes `request.env['omniauth.origin']` — which is populated from the attacker-controllable `origin` query parameter on the OAuth request phase and echoed back verbatim on callback — and passes it directly into `redirect_to` with no host/path validation. This lets an attacker craft a login link that, once the victim completes GitHub OAuth, redirects the freshly-authenticated browser to an arbitrary attacker-controlled URL.

### Finding Description
Broken binding: the code treats `request.env['omniauth.origin']` as if it were `== a URL scoped to Shipit.host`, but no such scoping is ever enforced.

```ruby
def callback
  return_url = request.env['omniauth.origin'] || root_path
  ...
  session[:user_id] = sign_in_github(auth)
  session[:authenticated] = true
  redirect_to(return_url)
end
``` [1](#0-0) 

The `origin` value is set by the app's `force_github_authentication` filter when it redirects unauthenticated visitors to `github_authentication_path(origin: request.original_url)`: [2](#0-1) 

That normal flow only ever sets `origin` to `request.original_url` (same host). However, `/github/auth/github` is the OmniAuth request-phase endpoint mounted by `OmniAuth::Builder`/`OmniAuth::Strategies::GitHub` at `path_prefix: '/github/auth'` [3](#0-2) . OmniAuth's core middleware (not this engine's code, but the mechanism this engine relies on) reads the `origin` query parameter directly from the incoming request at the request phase, stores it in the session, and restores it into `request.env['omniauth.origin']` at callback time — with no allow-list or same-host check. Nothing in this engine's controller re-validates that value before use in `redirect_to`. The existing test suite only confirms sign-in behavior, not the redirect target, and never asserts the value is constrained to `Shipit.host`: [4](#0-3) 

Attacker flow:
1. Attacker sends a victim a link: `https://shipit.example.com/github/auth/github?origin=https://evil.example.com`.
2. Victim clicks it; OmniAuth request phase stores `origin` and redirects to GitHub OAuth authorize.
3. Victim (already logged into GitHub, or completes login) authorizes the Shipit GitHub OAuth app.
4. GitHub redirects back to `/github/auth/github/callback`; OmniAuth restores `omniauth.origin` = `https://evil.example.com` into `request.env`.
5. `callback` sets `session[:user_id]`/`session[:authenticated] = true` (victim is now authenticated to Shipit) and then `redirect_to('https://evil.example.com')`.

No component in this engine (`force_github_authentication`, `User#authorized?`, model validators, etc.) validates the redirect target; those guards check *authorization to view stacks*, not the destination of this specific post-login redirect.

### Impact Explanation
The victim's browser, holding a now-valid Shipit session cookie, is sent to an attacker-chosen destination immediately after authenticating. This confirms to the attacker that the victim has a valid GitHub/Shipit account and enables phishing (e.g., a fake "session expired, re-enter your GitHub token" page) hosted at `evil.example.com`. It does not, by itself, leak `github_access_token` or `api_clients_secret` from Shipit's own code — the OAuth token exchange in this flow is server-side (`auth.credentials.token` is read from `request.env['omniauth.auth']`, not appended to `return_url`) — so the "combine with token leak in query string" escalation described in the prompt is not demonstrated in this codebase. The concrete, demonstrable impact is an open redirect immediately following authentication (matches the "High" bucket's "forced OAuth completion" framing loosely, though it is not session fixation nor unauthenticated data read).

### Likelihood Explanation
Preconditions: `Shipit.github.oauth?` must be true (default for any Shipit deployment using GitHub login) [3](#0-2) . The attacker needs no Shipit credentials, no repository access, and no privileged role — only the ability to send the victim a URL, satisfying the stated unprivileged-attacker model. Whether this is actually exploitable in a given deployment also depends on the Rails-level `raise_on_open_redirects` configuration in the *host application* (not present in this engine's own code/config), which — if enabled — would cause `redirect_to` to raise `ActionController::Redirecting::UnsafeRedirectError` for cross-host targets and neutralize the bug. This engine ships no such configuration itself, so as authored, the engine's controller performs no validation of its own.

### Recommendation
Validate `return_url` before redirecting: only allow relative paths or URLs whose host matches `Shipit.host`/`request.host`, e.g. using `URI.parse` to check `uri.host.nil? || uri.host == request.host`, falling back to `root_path` otherwise. Alternatively, explicitly pass `allow_other_host: false` to `redirect_to` (or upgrade to rely on `raise_on_open_redirects` at the app level) and add a same-host check specifically for `omniauth.origin` in `GithubAuthenticationController#callback`.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback rejects cross-host origin redirect targets" do
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
  @request.env['omniauth.origin'] = 'https://evil.example.com'

  get :callback

  # Binding under test: response location host should equal request.host (Shipit.host),
  # not the attacker-supplied 'https://evil.example.com'.
  refute_equal 'https://evil.example.com', response.location
  assert_equal URI.parse(response.location).host, @request.host
end
```
This test as written against the current implementation would fail (the redirect goes to `https://evil.example.com`), demonstrating the open redirect.

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

**File:** lib/shipit/engine.rb (L46-51)
```ruby
      if Shipit.github.oauth?
        OmniAuth::Strategies::GitHub.configure(path_prefix: '/github/auth')
        app.middleware.use(OmniAuth::Builder) do
          provider(:github, *Shipit.github.oauth_config)
        end
      end
```

**File:** test/controllers/github_authentication_controller_test.rb (L1-35)
```ruby
# frozen_string_literal: true

require 'test_helper'

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
end
```

### Title
Open redirect / OAuth origin injection in post-login redirect - ([File: app/controllers/shipit/github_authentication_controller.rb])

### Summary
`callback` redirects the freshly authenticated browser to `request.env['omniauth.origin']` with no allow-list, same-host, or format check. OmniAuth's default `request_phase` (used by `omniauth-github`) captures the `origin` query parameter unmodified and threads it through the OAuth flow into `omniauth.origin`, so an attacker-supplied `origin` value fully controls the post-authentication redirect target.

### Finding Description
The broken binding is: `request.env['omniauth.origin']` (the redirect target used at [1](#0-0) ) == a Shipit-controlled, same-origin path. This equality does not hold, because OmniAuth (via `omniauth-github`, required in [2](#0-1) ) sets `omniauth.origin` directly from the `origin` request parameter during the `/github/auth/github` request phase, with no validation performed anywhere in this engine.

Both legitimate call sites that build this URL — `force_github_authentication` in [3](#0-2)  — pass `request.original_url`, which is always same-host. But nothing prevents an attacker from directly requesting `/github/auth/github?origin=https://attacker.example.com` themselves, bypassing that code path entirely. The `callback` action then does:

```
return_url = request.env['omniauth.origin'] || root_path
...
redirect_to(return_url)
``` [4](#0-3) 

No host/scheme allow-list, no `only_path` enforcement, and no comparison against `request.host` exists in this controller or in `Shipit::Authentication`. The victim, after completing a real GitHub OAuth login (their session cookie now carries `session[:user_id]` and `session[:authenticated] = true`), is redirected off-host to the attacker's domain, at which point the `Referer` header (which will include the Shipit URL, potentially with sensitive query strings from whatever page originated the flow) is sent to the attacker, and any embedded token/URL in the redirect chain from a subsequent same-tab navigation could similarly leak.

### Impact Explanation
This is a classic OAuth/open-redirect vulnerability. It does not itself hand the attacker Shipit's session cookie (that remains scoped to the Shipit host and is not sent to attacker.example.com), so it does not achieve session hijacking or credential exfiltration on its own. It does, however, allow an attacker to complete a "forced" redirect of an authenticated victim to an arbitrary domain immediately after login, enabling phishing (a page that looks like Shipit and can prompt for GitHub re-auth) and leaking the `Referer` header. This matches the High-severity category of "session fixation / forced OAuth completion" in the rules, rather than Critical, since no secret or token is directly exfiltrated by this mechanism alone — the "ccmenu token in a redirect chain" scenario in the question is speculative and not demonstrated anywhere in this codebase.

### Likelihood Explanation
Attacker cost is minimal: get any user to click a link to `/github/auth/github?origin=https://attacker.example.com`. No Shipit credentials, webhook secrets, or privileged roles are required, consistent with the "unprivileged internet user" threat model. It is fully repeatable and not tied to any specific repository or stack.

### Recommendation
Validate `return_url` in `callback` before redirecting: only allow relative paths (e.g., via `Rack::Utils` or a regex ensuring the value starts with `/` and not `//`), or explicitly check that the parsed URL's host matches `request.host` before calling `redirect_to`. Reject/ignore any `omniauth.origin` that isn't a same-host relative path and fall back to `root_path`.

### Proof of Concept
```ruby
# test/controllers/github_authentication_controller_test.rb
test ":callback does not redirect off-host when origin is external" do
  auth = OmniAuth::AuthHash.new(
    credentials: OmniAuth::AuthHash.new(token: 's3cr3t'),
    extra: OmniAuth::AuthHash.new(raw_info: OmniAuth::AuthHash.new(
      id: 44, name: 'Shipit User', email: 'shipit-user@example.com',
      login: 'shipit-user', avatar_url: 'https://example.com',
      api_url: 'https://github.com/api/v3/users/shipit-user'
    ))
  )
  @request.env['omniauth.auth'] = auth
  @request.env['omniauth.origin'] = 'https://attacker.example.com'

  get :callback

  refute_match(/attacker\.example\.com/, response.location, "must not redirect off-host")
end
```
Under the current implementation, `response.location` equals `https://attacker.example.com`, proving the divergence; after the recommended fix it should fall back to `root_path`.

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

**File:** lib/shipit.rb (L20-20)
```ruby
require 'omniauth-github'
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

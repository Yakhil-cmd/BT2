## Root cause

Shipit supports mounting **multiple independent GitHub Apps/OAuth clients for multiple GitHub organizations** (including separate GitHub Enterprise domains) via `config/secrets.yml`, each with its own `app_id`, `oauth`, and `webhook_secret` [1](#0-0) [2](#0-1) . Each organization can even override `domain` to point at a distinct GitHub Enterprise install [3](#0-2) .

However, all of these organizations feed into a **single shared OAuth callback route/controller** (`/github/auth/github/callback` → `GithubAuthenticationController#callback`) [4](#0-3) , and that controller resolves the Shipit `User` to bind to the session purely from the numeric `github_id` in the OAuth payload, with no scoping by which organization/domain's OAuth app performed the authentication:

```ruby
def sign_in_github(auth)
  user = User.find_or_create_from_github(auth.extra.raw_info)
  user.update(github_access_token: auth.credentials.token)
  user.id
end
``` [5](#0-4) 

```ruby
def self.find_or_create_from_github(github_user)
  find_from_github(github_user) || create_from_github(github_user)
end

def self.find_from_github(github_user)
  return unless github_user.id
  find_by(github_id: github_user.id)
end
``` [6](#0-5) 

`session[:user_id]` is then set from this lookup and is trusted engine-wide by `Authentication#current_user` / `find_current_user` to authorize access, team membership checks, and identity for every action taken afterward [7](#0-6) .

## The broken binding

`github_id` values are only guaranteed unique **within a single GitHub instance** (github.com, or a specific GitHub Enterprise install). They are not globally unique across independently-administered GitHub instances — Enterprise installs assign their own sequential numeric IDs starting from 1, so low IDs on one Enterprise instance routinely collide with real users' IDs on github.com or on another configured Enterprise instance.

Because the callback path never records or checks *which organization's OAuth app* authenticated the request, `find_by(github_id: ...)` binds the session to whatever pre-existing `User` row happens to share that numeric ID — regardless of whether it was created via the github.com App or via a different, independently trusted Enterprise App. This is exactly the class of bug in the report generalized to this codebase: a value (`github_id`) that is authoritative only in a narrower scope (single GitHub instance) is used to satisfy a broader, unscoped lookup that grants a security-relevant binding (the session's `User` identity), i.e. **the GitHub identity a specific OAuth app actually vouches for ≠ the `User` record the session binds to.**

## Practical exploitability caveat

I could not find any code that scopes `User` by organization/domain (no `domain`/`organization` column on `users`, and I was unable to fully inspect `test/dummy/db/schema.rb` for a `github_id` uniqueness constraint scoped by anything other than the column itself). This means the collision is architecturally possible whenever an operator configures more than one GitHub App/organization (which is a documented, supported configuration, not a misconfiguration outside the engine's control). An attacker only needs an account on *any* configured, lower-trust GitHub organization/Enterprise instance whose numeric account ID matches a targeted, higher-privilege Shipit user's `github_id` on another configured organization — no Shipit session, API token, or repository write access is a prerequisite to attempt the OAuth flow itself.

I was not able to fully verify from the index whether Shipit deployments in the wild commonly combine github.com with a self-administered Enterprise instance controlled by a lesser-privileged party (this is an operational/deployment fact outside the code), so likelihood depends on that operator choice, which the engine does not prevent or warn about.

### Title
Cross-organization GitHub identity collision allows session hijack via `User#find_from_github` unscoped `github_id` lookup - (File: `app/models/shipit/user.rb`, `app/controllers/shipit/github_authentication_controller.rb`)

### Summary
When Shipit is configured with multiple GitHub Apps/organizations (a documented supported configuration, optionally spanning different GitHub Enterprise domains), the shared OAuth callback binds the Shipit session to a `User` looked up solely by numeric `github_id`, without regard to which organization's/domain's OAuth app produced that identity. Because `github_id` is only unique per GitHub instance, an attacker with an account on one configured (lower-trust) GitHub org/Enterprise instance whose ID collides with a legitimate user's ID on another configured org can authenticate and have `session[:user_id]` set to that legitimate user's `User` record.

### Finding Description
`GithubAuthenticationController#sign_in_github` calls `User.find_or_create_from_github(auth.extra.raw_info)` and stores the resulting user's `id` in `session[:user_id]` [8](#0-7) . `User.find_from_github` performs `find_by(github_id: github_user.id)` [6](#0-5)  with no organization/domain scoping, even though `Shipit.github(organization:)` explicitly supports multiple independently configured GitHub Apps/organizations, each potentially pointed at a different `domain` (github.com vs. a GitHub Enterprise install) [9](#0-8) [1](#0-0) . All organizations share one OAuth callback route (`/github/auth/github/callback`) and controller [4](#0-3) . The resulting session is trusted engine-wide for authorization decisions, including team-membership checks in `Authentication#force_github_authentication` [10](#0-9) .

### Impact Explanation
This breaks the equality "the GitHub identity that actually authenticated == the `User` the session is bound to." An attacker whose account on one configured GitHub org/Enterprise instance shares a numeric `github_id` with a privileged Shipit user on a different configured org can hijack that user's session, escalating into `Shipit.github_teams` authorization and potentially acting with that user's privileges (e.g. creating `ApiClient`s, triggering deploys) — meeting the High/Critical bar for authorization bypass and unauthorized actions.

### Likelihood Explanation
Requires the operator to have configured Shipit with multiple GitHub Apps/organizations spanning different GitHub instances (a documented, supported feature, not a misconfiguration) and requires an ID collision, which is plausible for low-numbered accounts on self-hosted GitHub Enterprise instances that assign IDs starting at 1. No privileged Shipit credential, repository write access, or social engineering is needed — only completing a normal OAuth login on one of the configured orgs.

### Recommendation
Scope `User` lookup/creation by the authenticating organization/domain (e.g., store and match on `(domain, github_id)` or `(organization, github_id)` rather than `github_id` alone), and have `GithubAuthenticationController#callback` pass through and enforce which configured organization initiated the OAuth request when resolving the `User`.

### Proof of Concept
1. Operator configures Shipit with two organizations in `secrets.yml`: `OrgOne` (github.com) and `OrgTwo` (Enterprise domain `github.example.com`), as in the supported multi-org example [3](#0-2) .
2. A privileged Shipit user, `victim`, has `github_id = 42` on github.com (`OrgOne`).
3. Attacker, who administers or holds an account on the `OrgTwo` Enterprise instance, creates/uses an account there whose `github_id` is also `42` (plausible since Enterprise IDs are sequential and independently assigned).
4. Attacker completes OAuth against `OrgTwo`'s app at `/github/auth/github/callback`.
5. `User.find_from_github` matches the existing `victim` row via `find_by(github_id: 42)`, and `session[:user_id]` is set to `victim.id` — the attacker is now logged in as `victim`.

### Citations

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

**File:** lib/shipit/github_app.rb (L34-57)
```ruby
    DOMAIN = 'github.com'
    AuthenticationFailed = Class.new(StandardError)
    API_STATUS_ID = 'brv1bkgrwx7q'

    GITHUB_EXPECTED_TOKEN_LIFETIME = 60.minutes
    GITHUB_TOKEN_RAILS_CACHE_LIFETIME = 50.minutes
    GITHUB_TOKEN_REFRESH_WINDOW = GITHUB_EXPECTED_TOKEN_LIFETIME - GITHUB_TOKEN_RAILS_CACHE_LIFETIME - 2.minutes

    attr_reader :oauth_teams, :domain, :bot_login

    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
    end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-46)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L7-34)
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

    def logout
      reset_session
      redirect_to(root_path)
    end

    private

    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

**File:** app/models/shipit/user.rb (L46-54)
```ruby
    def self.find_or_create_from_github(github_user)
      find_from_github(github_user) || create_from_github(github_user)
    end

    def self.find_from_github(github_user)
      return unless github_user.id

      find_by(github_id: github_user.id)
    end
```

**File:** app/controllers/concerns/shipit/authentication.rb (L18-42)
```ruby
    private

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

    def current_user
      @current_user ||= find_current_user || AnonymousUser.new
    end

    def find_current_user
      session[:user_id].present? && User.find_by(id: session[:user_id])
    end
```

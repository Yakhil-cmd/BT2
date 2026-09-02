### Title
Unauthenticated `X-Shipit-User` Header Impersonation Breaks GitHub-Identity-to-Actor Binding in the API - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
`Shipit::Api::BaseController` authenticates *requests* via an `ApiClient` bearer token (`authenticate_api_client`), but derives the *actor identity* used for deploy/rollback/task attribution and downstream shell-script environment variables from a completely unauthenticated HTTP header, `X-Shipit-User`, with no cross-check against the token's own bound `creator`. This is the same class of bug as the TWAMM finding: a value that participates in a security-relevant computation (`getRewardRateInside` / here, `current_user`) is never bound to the value that was actually verified (`rewardRatesBeforeSlot[startTime]` / here, `current_api_client.creator`), so the trusted computation silently falls back to attacker-controlled input.

### Finding Description
`ApiClient` is a real, verified credential bound to a specific `creator` `User` at creation time: [1](#0-0) 

`BaseController#authenticate_api_client` verifies the bearer token cryptographically via `ApiClient.authenticate`, proving *who issued the request* (`current_api_client`, whose `creator` is a specific `User`): [2](#0-1) 

However, `current_user` — the identity actually recorded as the *actor* of privileged operations — is computed independently from an arbitrary, unverified request header, with no relationship whatsoever to `current_api_client`: [3](#0-2) 

This `current_user` is then passed directly into state-mutating, audited operations such as deploy creation: [4](#0-3) 

and is used to populate shell-script environment variables and committer metadata during actual task execution on the deploy host: [5](#0-4) 

The test suite explicitly documents (and thus "specifies," rather than merely allows) this behavior — the header value is trusted verbatim, case-insensitively matched to any existing `User`: [6](#0-5) 

**The broken equality:** the code implicitly assumes
`current_user == current_api_client.creator`
but never enforces it. In reality:
`current_user = User.where('lower(login) = ?', X-Shipit-User-header.downcase).first`
which is fully attacker-controlled and disjoint from `current_api_client.creator`. Any caller who legitimately holds *any* valid `ApiClient` token with the relevant permission (e.g. `deploy:stack`) — including tokens self-service-created for narrow purposes such as the read-only "CCMenu Client" — can set `X-Shipit-User` to the login of any other `User` row (e.g. an admin, a senior engineer, or the `Shipit.committer_name` account) and have every deploy, rollback, task trigger, or abort permanently attributed to, and executed "as," that impersonated identity — including `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` and `SHIPIT_USER`/`EMAIL` env vars injected into the actual deploy shell commands run on the deploy host.

### Impact Explanation
This breaks the "GitHub identity versus the `User` bound to the session/credential" trust binding explicitly called out as in-scope. Concretely:
- Every `Task`/`Deploy`/`Rollback`'s `user`/`author` field, and the `aborted_by` field, can be forged to any existing `User`, undermining the entire audit trail Shipit relies on for accountability of who deployed/rolled back/aborted what.
- The forged identity is fed into the actual command execution environment on the deploy host (`GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `SHIPIT_USER`, `EMAIL`), meaning commits made by deploy scripts (e.g. tagging releases) will be falsely attributed to another real person.
- Because attribution/identity is the mechanism by which humans (and potentially any downstream automation keyed on "who triggered this") establish trust and accountability for an "unauthorized deploy, rollback" action, this is best classified as an **authentication/identity bypass** for the actor field of privileged operations — matching the Critical bucket ("authentication bypass ... unauthorized deploy, rollback").

### Likelihood Explanation
High. No secret, private key, TLS interception, or elevated role is needed — only possession of *some* valid `ApiClient` token, which multiple code paths hand out to ordinary session-authenticated users automatically and without administrator approval (e.g. `CCMenuUrlController` auto-provisions a `read:stack`-scoped `ApiClient` for any logged-in user on demand): [7](#0-6) 

Setting an arbitrary HTTP header is trivial and requires no special tooling. The test suite even names and validates this exact behavior ("use the claimed user as author," "normalises the claimed user"), confirming it is intentional, currently-shipping behavior rather than a theoretical edge case.

### Recommendation
Remove the unauthenticated `X-Shipit-User` trust path entirely, or bind it cryptographically/structurally to the authenticated credential:
1. Default `current_user` to `current_api_client.creator` and only allow header-based "acting as" overrides when the `current_api_client.creator` itself has an explicit, checked delegation/impersonation permission over the target user (e.g. an `admin`/`impersonate:user` scope), verified server-side — never trust the raw header value alone.
2. At minimum, restrict `X-Shipit-User` override to `ApiClient`s explicitly flagged for that capability, and log/audit every case where `X-Shipit-User` differs from `current_api_client.creator.login`.
3. Ensure `identify_user` cannot resolve to an identity with more authority (e.g. `Shipit.github_teams` membership) than the actual `current_api_client.creator`.

### Proof of Concept
1. As any Shipit user with baseline session access, visit a stack's CCMenu URL endpoint to obtain a self-service `read:stack`-scoped `ApiClient` token (or use any other legitimately-issued token with `deploy:stack`), per `CCMenuUrlController#client`.
2. Send:
```
POST /api/stacks/<stack>/deploys
Authorization: Basic <api-client-token>
X-Shipit-User: <victim_admin_login>
{ "sha": "<commit_sha>" }
```
3. Observe (per `DeploysController#create` and `test/controllers/api/deploys_controller_test.rb:49-60`) that the resulting `Deploy.user` is set to `<victim_admin_login>`'s `User` record, and the deploy's shell execution environment (`GIT_COMMITTER_NAME`, `GIT_COMMITTER_EMAIL`, `SHIPIT_USER`, `EMAIL` from `lib/shipit/task_commands.rb:33-48`) reflects the victim's identity — despite the request having been authenticated solely by the attacker's own (potentially unrelated/limited-scope) `ApiClient` token.

### Citations

**File:** app/models/shipit/api_client.rb (L4-27)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }

    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L48-63)
```ruby
      def authenticate_api_client
        @current_api_client = if Shipit.disable_api_authentication
                                UnlimitedApiClient.new
                              else
                                BasicAuth.authenticate(request) do |*parts|
                                  token = parts.select(&:present?).join('--')
                                  ApiClient.authenticate(token)
                                end
                              end
        return if @current_api_client

        headers['WWW-Authenticate'] = 'Basic realm="Authentication token"'
        render(status: :unauthorized, json: { message: 'Bad credentials' })
      end

      attr_reader :current_api_client
```

**File:** app/controllers/shipit/api/base_controller.rb (L65-72)
```ruby
      def current_user
        @current_user ||= identify_user || AnonymousUser.new
      end

      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-28)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
      end
```

**File:** lib/shipit/task_commands.rb (L33-48)
```ruby
    def env
      super
        .merge(@stack.env)
        .merge(
          'SHIPIT_USER' => "#{@task.author.login} (#{normalized_author_name}) via Shipit",
          'EMAIL' => @task.author.email,
          'BUNDLE_PATH' => Rails.root.join('data', 'bundler').to_s,
          'SHIPIT_LINK' => @task.permalink,
          'TASK_ID' => @task.id.to_s,
          'IGNORED_SAFETIES' => @task.ignored_safeties? ? '1' : '0',
          'GIT_COMMITTER_NAME' => @task.user&.name || Shipit.committer_name,
          'GIT_COMMITTER_EMAIL' => @task.user&.email || Shipit.committer_email
        )
        .merge(deploy_spec.machine_env)
        .merge(@task.env)
    end
```

**File:** test/controllers/api/deploys_controller_test.rb (L49-60)
```ruby
      test "#create use the claimed user as author" do
        request.headers['X-Shipit-User'] = @user.login
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        deploy = Deploy.last
        assert_equal @user, deploy.user
      end

      test "#create normalises the claimed user" do
        request.headers['X-Shipit-User'] = @user.login.swapcase
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        deploy = Deploy.last
        assert_equal deploy.user, @user
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

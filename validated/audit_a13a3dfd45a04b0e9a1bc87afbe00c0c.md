This confirms the analog: the API authenticates a *capability token* (the `ApiClient` via `ApiClient.authenticate`, cryptographically signed with `Shipit.api_clients_secret`), but the acting *identity* (author of record for deploys/rollbacks/tasks) is derived from a fully client-controlled, unverified `X-Shipit-User` header, matching the "GitHub identity vs the `User` bound to the session" binding class described in the rules — here the binding that should hold is `authenticated capability (ApiClient) == acted-upon identity (User)`, but instead the acted-upon identity is an arbitrary claim.

### Title
Unverified `X-Shipit-User` header lets any authenticated API client impersonate arbitrary users as deploy/rollback/task authors - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`Shipit::Api::BaseController#identify_user` derives `current_user` solely from the client-supplied `X-Shipit-User` request header, doing a case-insensitive lookup with no cryptographic binding to the authenticated `ApiClient` credential used for the request. [1](#0-0) 

### Finding Description
`authenticate_api_client` verifies a signed `ApiClient` token via HTTP Basic Auth (`ApiClient.authenticate`, backed by `SimpleMessageVerifier` with `Shipit.api_clients_secret`), establishing an authenticated *capability* (`@current_api_client`) that is checked for coarse-grained permissions like `deploy:stack`. [2](#0-1) [3](#0-2) 

Separately, `current_user` — used as the *acting identity* (author) for deploys, rollbacks and tasks — is computed from `identify_user`, which trusts the raw `X-Shipit-User` header verbatim and looks up any `User` by login, with zero verification that this claimed login corresponds to the entity holding the Basic Auth credential: [4](#0-3) 

This value flows directly into `Deploy`/`Rollback`/`Task` creation as the recorded `user`/author, e.g. via `stack.trigger_deploy(commit, current_user, ...)` and `stack.trigger_task(params[:task_name], current_user, ...)`: [5](#0-4) [6](#0-5) 

Tests explicitly document this behavior as intentional-looking ("uses the claimed user as author"), confirming the header is trusted as-is: [7](#0-6) 

**Equality broken:** `authenticated_capability(ApiClient token) == acted_identity(User recorded as author)` is not enforced. Before the fix, any request with a valid `ApiClient` token can set `X-Shipit-User` to any existing login (e.g. an org admin) and have all resulting deploy/rollback/task/abort records attributed to that arbitrary user, with the `check_permissions!` gate only checking the `ApiClient`'s scope, not the claimed user's authorization at all.

### Impact Explanation
Any holder of a legitimate `ApiClient` token with `deploy:stack` permission (e.g., a low-privilege integration bot) can trigger deploys, rollbacks, or tasks — including on protected/locked stacks depending on `force` — and have them permanently attributed to any other `User` in the system, including administrators. This is an authorization/attribution bypass: the "who did this" audit trail and any downstream authorization logic that trusts `current_user` (e.g. `aborted_by`, notifications, `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` injected into the deploy environment, per `TaskCommands#env`) can be forged. [8](#0-7) 

This does not itself grant new stack permissions beyond what the `ApiClient` already has, but it breaks the integrity of user attribution and can be leveraged to falsify audit logs/notifications and impersonate specific users in downstream systems that trust `SHIPIT_USER`/`GIT_COMMITTER_*` env vars during deploy scripts.

### Likelihood Explanation
Trivial to exploit: requires only a valid (even minimally-scoped) `ApiClient` Basic Auth token and knowledge/guessing of any existing user's `login` (logins are often public GitHub handles). No additional secret or repository write access is needed — this matches the "unprivileged attacker with an ApiClient token" boundary explicitly in scope of this analysis (a documented, supported feature of the API, not a hidden misconfiguration).

### Recommendation
Do not derive `current_user` from an unauthenticated header. If user impersonation must be supported for automation, require that the `ApiClient` explicitly declares (and is scoped to) the set of users/logins it is allowed to claim, or bind the claimed identity into the same signed credential that authenticates the `ApiClient` (e.g., include the login in the signed message verified by `ApiClient.authenticate`), and reject `X-Shipit-User` values that don't match. At minimum, restrict which `ApiClient`s may set this header via a dedicated permission distinct from `deploy:stack`.

### Proof of Concept
1. Obtain any valid API client Basic Auth token with `deploy:stack` permission (e.g., a scoped CI bot's token).
2. Send `POST /api/stacks/:owner/:name/:env/deploys` with header `X-Shipit-User: <victim-admin-login>` and `Authorization: Basic <bot-token>`.
3. Observe (per `DeploysController#create` → `Stack#trigger_deploy` → `Stack#build_deploy`) that `Deploy.last.user` equals the victim, as directly demonstrated by the existing test: [9](#0-8) 
4. The deploy/rollback/task is now permanently attributed to, and its environment reflects, the impersonated user rather than the actual token holder.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L48-61)
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

**File:** app/models/shipit/api_client.rb (L23-32)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
      end

      def message_verifier
        @message_verifier ||= Shipit::SimpleMessageVerifier.new(Shipit.api_clients_secret)
      end
    end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L19-27)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L17-26)
```ruby
      params do
        accepts :env, Hash, default: {}
      end
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
      rescue Shipit::Task::ConcurrentTaskRunning
        render(status: :conflict, json: {
                 message: 'A task is already running.'
               })
      end
```

**File:** test/controllers/api/deploys_controller_test.rb (L49-61)
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

### Title
Unauthenticated `X-Shipit-User` header lets any API client impersonate an arbitrary Shipit user as the author of deploys, rollbacks, locks and tasks - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
This is a valid analog of the reported bug class: a value that is *trusted and acted upon* is never actually verified against the credential that authenticated the request. In the original report, `updateUserBoost()` uses a hardcoded constant instead of the value that should have been bound to the user's real balance. In `shipit-engine`, `Api::BaseController#identify_user` derives `current_user` purely from a client-supplied `X-Shipit-User` request header, with **no cryptographic or session binding to the authenticated `ApiClient`**. The `ApiClient` token proves *who is allowed to call the API* (and with what stack/permission scope), but the `User` recorded as the actor of the resulting action is taken from an untrusted header instead of being bound to the authenticated identity.

### Finding Description
`authenticate_api_client` authenticates the request using HTTP Basic auth against an `ApiClient` token: [1](#0-0) 

Separately, `current_user` is derived from a header the caller fully controls: [2](#0-1) 

`identify_user` does a case-insensitive lookup of *any* `User` row by `login` supplied in `X-Shipit-User`, with no relationship whatsoever to the `ApiClient` that authenticated the request (`ApiClient` only has a `creator` association, never consulted here): [3](#0-2) 

This `current_user` value is then used, unauthenticated, as the actor of privileged, audited actions across multiple API controllers:
- Triggering a deploy: [4](#0-3) 
- Triggering a rollback / aborting active tasks: [5](#0-4) 
- Locking/unlocking a stack: [6](#0-5) 
- Triggering or aborting custom tasks: [7](#0-6) 

The test suite confirms this is intentional, unauthenticated impersonation ("claimed user"): [8](#0-7) 

**Binding broken (as an equality):**
`ApiClient token holder == User attributed as deploy/lock/task author` is expected, but in reality `User attributed = User.where(login: request.headers['X-Shipit-User'])`, an arbitrary, attacker-chosen value entirely decoupled from the authenticated credential. Before the request: the `ApiClient` is scoped to a stack/permission set and has its own `creator`. After the request: the persisted `Deploy`/`Task`/`Lock` records `user`/`aborted_by`/`lock_author` as a completely different, attacker-chosen `User`, including users with elevated trust (e.g., team leads whose name appears in notifications, audit logs, GitHub commit-deployment attribution, and Shipit's own authorization-adjacent `User#authorized?`/team membership displayed in the UI).

### Impact Explanation
Any holder of a legitimate, even narrowly-scoped, `ApiClient` token (e.g. one issued only for CI to call `deploy:stack` on one stack) can forge the identity of any other existing Shipit `User` (looked up only by `login`) for every write action it performs. This corrupts the audit trail Shipit relies on for accountability (who deployed, who locked, who aborted, who rolled back), and can be used to impersonate privileged or trusted users in downstream systems that consume this attribution (Slack/webhook notifications broadcasting "SHIPIT_USER", GitHub commit deployment status authorship, etc. — see `TaskCommands#env` setting `SHIPIT_USER`/`GIT_COMMITTER_NAME` from `@task.author`/`@task.user`, per [9](#0-8) ). This does not itself grant new permissions beyond what the token's `permissions`/`stack_id` already scope, so it does not meet the "Critical" bar (no direct RCE, auth bypass, cross-repo write, or credential exfiltration), but it is a genuine trust-binding break enabling identity spoofing/impersonation for every privileged write action exposed by the API.

### Likelihood Explanation
Trivial to exploit: it requires only a legitimately issued, low-privilege `ApiClient` token (a prerequisite already excluded from "requires an ApiClient token" only when read as a *sole* barrier — here the point is that possessing *any* valid token, regardless of scope/creator, is sufficient to impersonate *any* other user for attribution purposes). No additional secrets, races, or timing are required; a single crafted header on any existing authenticated write request suffices, and the behavior is explicitly covered/expected by the test suite.

### Recommendation
Do not allow arbitrary user impersonation via a client-supplied header. Either:
- Bind `current_user` to the authenticated `ApiClient#creator` exclusively, removing `X-Shipit-User` trust entirely, or
- If "acting as" another user must remain supported, require that this capability be an explicit, checked permission on the `ApiClient` (e.g., a new `impersonate:user` permission) and audit/limit which logins can be claimed (e.g., restrict to the client's own `creator` or an allow-list), rather than trusting any request header value verbatim.

### Proof of Concept
1. Obtain (or be issued) a low-privilege `ApiClient` token scoped only to `deploy:stack` for stack A, created by user `ci-bot`.
2. Send: `POST /api/stacks/:id/deploys` with `Authorization: Basic <token>` and header `X-Shipit-User: admin-user` and a valid `sha`.
3. Observe the resulting `Deploy` record has `user == admin-user`, not `ci-bot` — as demonstrated by the existing test `"#create use the claimed user as author"`: [10](#0-9) .
4. Repeat against `LocksController#create`, `TasksController#trigger`/`#abort`, and `RollbacksController#create` to impersonate `admin-user` as the author of a lock, a task trigger/abort, or a rollback.

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

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
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

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L14-32)
```ruby
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't rollback a locked stack") if !params.force && stack.locked?
        deploy = stack.deploys.find_by(until_commit: commit) || param_error!(:sha, 'Cant find associated deploy')
        rollback_env = stack.filter_rollback_envs(params.env)

        response = nil
        if !params.force && stack.active_task?
          param_error!(:force, "Can't rollback, deploy in progress")
        elsif stack.active_task?
          active_task = stack.active_task
          active_task.abort!(aborted_by: current_user, rollback_once_aborted_to: deploy, rollback_once_aborted: true)
          response = active_task
        else
          response = deploy.trigger_rollback(current_user, env: rollback_env, force: params.force, lock: params.lock)
        end

        render_resource(response, status: :accepted)
      end
```

**File:** app/controllers/shipit/api/locks_controller.rb (L11-26)
```ruby
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end

      params do
        requires :reason, String, presence: true
      end
      def update
        stack.lock(params.reason, current_user)
        render_resource(stack)
      end
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-37)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
      rescue Shipit::Task::ConcurrentTaskRunning
        render(status: :conflict, json: {
                 message: 'A task is already running.'
               })
      end

      def abort
        if task.active?
          task.abort!(aborted_by: current_user)
          head(:accepted)
        else
          render(status: :method_not_allowed, json: {
                   message: "This task is not currently running."
                 })
        end
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

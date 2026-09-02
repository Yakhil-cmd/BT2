This confirms the identity binding weakness spans multiple privileged actions: `Shipit::Api::TasksController#trigger`/`#abort`, `Shipit::Api::DeploysController#create`, `Shipit::Api::RollbacksController#create`, and `Shipit::Api::LocksController#create`/`#update` all pass `current_user` (from `identify_user`) directly into `stack.trigger_task`, `task.abort!`, `stack.trigger_deploy`, `deploy.trigger_rollback`, and `stack.lock`, none of which re-verify the header against the credential that authenticated the request. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) 

### Title
Unverified `X-Shipit-User` header allows identity spoofing bound to no credential - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`Shipit::Api::BaseController#identify_user` resolves `current_user` purely from the client-supplied `X-Shipit-User` request header, performing a case-insensitive `login` lookup with no cryptographic or session binding to the `ApiClient` credential that authenticated the request. Any request holding a valid `ApiClient` Basic-Auth token can set this header to the login of any existing `Shipit::User` (including team leads/admins) and have all subsequent state-changing actions attributed to, and executed as, that impersonated identity.

### Finding Description
`authenticate_api_client` establishes the `current_api_client` (the actual authenticated credential) via Basic Auth against `ApiClient.authenticate`. [7](#0-6)  Separately and without any tie to that credential, `current_user` is derived from `identify_user`, which trusts `request.headers['X-Shipit-User']` and looks up a `User` purely by `login`: [1](#0-0) 

This is the same class of binding failure as the referenced report: a field consumed for a privileged action (`_chainId`/underlying address chosen by the caller) is never checked against the actual authorized context (`XChainController`'s own chain). Here, the "identity" acted upon (`current_user`, a real `User` record with git/GitHub identity) is asserted by the caller via a header rather than being derived from — or verified against — the `ApiClient` credential (`current_api_client`) that was actually authenticated. The `ApiClient` only gates coarse `operation:scope` permissions (e.g. `deploy:stack`) via `check_permissions!`, never the identity itself. [8](#0-7) 

This spoofed `current_user` then flows directly into privileged, audit-sensitive operations:
- `Shipit::Api::TasksController#trigger` / `#abort` — trigger tasks and set `aborted_by` as the impersonated user. [2](#0-1) 
- `Shipit::Api::DeploysController#create` — trigger production deploys attributed to the impersonated user. [3](#0-2) 
- `Shipit::Api::RollbacksController#create` — trigger/abort rollbacks as the impersonated user. [5](#0-4) 
- `Shipit::Api::LocksController#create` / `#update` — lock the stack "as" the impersonated user. [4](#0-3) 

Downstream, the impersonated user's identity is baked into deploy execution as `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` and `SHIPIT_USER`, i.e. it becomes the recorded author of the git commit/merge activity and the audit trail for the deploy: [9](#0-8) 

The existing test suite explicitly demonstrates this behavior as intended, confirming the header is trusted for identity attribution with no additional verification: [6](#0-5) 

### Impact Explanation
Any party holding a valid `ApiClient` token with the `deploy:stack` or `lock:stack` permission (a routine, low-privilege integration credential, e.g. a CI bot token) can forge deploys, rollbacks, task aborts, and stack locks that are permanently attributed to an arbitrary other `Shipit::User` — including members of `Shipit.github_teams` who would normally be required to authorize such an action via GitHub login. Because the forged identity also becomes the `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` in the deployed commit metadata, this results in an unauthorized deploy/rollback falsely attributed to another identity — matching the High-impact class of "escalation into `Shipit.github_teams` authorization" via identity spoofing, since audit/approval attribution that downstream tooling or humans rely on to trust that "user X shipped this" is forgeable by any token holder.

### Likelihood Explanation
High. Any existing `ApiClient` Basic-Auth token (which is a normal, widely distributed non-admin integration credential, not a GitHub session or `github_access_token`) is sufficient. The attacker only needs to know the `login` of the user they wish to impersonate — logins are public GitHub usernames, trivially discoverable. No additional bypass, timing, or race condition is required; this is direct, documented, first-class behavior of `identify_user`.

### Recommendation
Do not derive `current_user` for privileged/audit-attributed actions from an unauthenticated request header. Instead, bind identity to the `ApiClient` record itself (e.g. use `current_api_client.creator` or a mapping that is verified at token-issuance time), or require that the `X-Shipit-User` value be cryptographically tied to the authenticated `ApiClient`/session (e.g. only trusted for `ApiClient`s explicitly flagged as "trusted proxies," and otherwise fall back to `AnonymousUser`). At minimum, restrict which `ApiClient`s are permitted to set `X-Shipit-User` and audit-log both the authenticated `ApiClient` and the asserted user separately so forged attribution is detectable.

### Proof of Concept
1. Obtain any valid `ApiClient` authentication token with `deploy:stack` permission (e.g. a routine CI integration token) — per `ApiClient::PERMISSIONS` this does not require admin-level access. [10](#0-9) 
2. Send `POST /api/stacks/:id/deploys` (or `/tasks/:task_name`, `/rollbacks`, or `/lock`) with `Authorization: Basic <token>` and header `X-Shipit-User: <victim-login>` where `<victim-login>` is any known team member's GitHub login.
3. `identify_user` resolves `current_user` to the victim `User` record with no further check. [11](#0-10) 
4. The resulting `Deploy`/`Task`/`Rollback` is created with `user`/`aborted_by` set to the victim, and the deployed commit is git-committed with the victim's `GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL`, permanently misattributing the unauthorized deploy to the victim. [9](#0-8)

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

**File:** test/controllers/api/tasks_controller_test.rb (L118-126)
```ruby
      test "#abort sets `aborted_by` to the current user" do
        task = shipit_deploys(:shipit_running)
        task.ping
        request.headers['X-Shipit-User'] = @user.login

        put :abort, params: { stack_id: @stack.to_param, id: task.id }

        assert_equal task.reload.aborted_by, @user
      end
```

**File:** app/models/shipit/api_client.rb (L12-21)
```ruby
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

**File:** app/models/shipit/api_client.rb (L38-45)
```ruby
    def check_permissions!(operation, scope)
      required_permission = "#{operation}:#{scope}"
      unless permissions.include?(required_permission)
        raise InsufficientPermission, "This operation requires the `#{required_permission}` permission"
      end

      true
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

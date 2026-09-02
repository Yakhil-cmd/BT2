### Title
X-Shipit-User header lets any authenticated ApiClient impersonate an arbitrary GitHub identity as deploy/task/rollback/lock author - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
The Sherlock finding is a DOS caused by a mismatched trust binding between a value the protocol accepts (a withdrawal request) and the constraint that actually governs it (the redemption queue's real unlock time), letting an attacker exploit the gap between "authorized" and "actually enforced." The closest reachable analog in `shipit-engine` is a credential/identity binding gap: the API layer authenticates the caller as an `ApiClient` (a token, tied to a `creator`), but then binds all subsequent write actions (deploys, rollbacks, task triggers, locks) to a completely different, unauthenticated identity taken from a client-supplied HTTP header.

### Finding Description
`Shipit::Api::BaseController` authenticates requests via HTTP Basic Auth against an `ApiClient` token: [1](#0-0) 

Separately, `current_user` — the identity that is actually recorded as the *author* of the resulting action — is derived not from the authenticated `ApiClient`/its `creator`, but from an arbitrary request header: [2](#0-1) 

This `current_user` is passed straight into privileged, side-effecting actions across the API surface:
- Triggering a deploy: [3](#0-2) 
- Triggering/aborting a task: [4](#0-3) 
- Triggering a rollback / aborting active task: [5](#0-4) 
- Locking a stack: [6](#0-5) 

The test suite explicitly documents and asserts this behavior: any request bearing a valid `ApiClient` token (irrespective of which user created that client or what that client is meant to represent) can set `X-Shipit-User` to any existing GitHub login and the resulting `Deploy`/`Task`/`Rollback` record will be attributed to that claimed user: [7](#0-6) 

The binding that should hold is: `GitHub identity that authorizes the action == User object bound to and recorded for the action`. Instead, the engine enforces: `ApiClient token authorizes the action` (permission scope, e.g. `deploy:stack`) while `attacker-supplied X-Shipit-User header == User bound to the action`. These are two unrelated axes — the permission check (`ApiClient#check_permissions!`) never verifies that the claimed `X-Shipit-User` corresponds to the entity that owns/created the `ApiClient`, or to any team membership required elsewhere in the app (e.g., `Shipit.github_teams` checks enforced only in the session-based web UI, not here): [8](#0-7) 

By contrast, the session-based web controllers require actual GitHub OAuth membership in `Shipit.github_teams` (see `ApiClientsControllerTest`'s team-membership check), but this equivalent enforcement is entirely absent from the API-token path when it comes to attributing/authoring actions — the "identity" of the acting user is taken purely from client input.

### Impact Explanation
Any party holding an `ApiClient` token with `deploy:stack`, `lock:stack`, or task-trigger permission — regardless of who legitimately created/owns that token — can attribute deploys, rollbacks, task executions, and stack locks/unlocks to any other user in the system (e.g., a senior engineer, an on-call lead, or a bot identity used for auto-approval logic). Downstream code that trusts `Task#author`/`Deploy#user` for authorization decisions, audit trails, notifications, or "who approved this" semantics can be misled. This does not itself grant a *new* permission (the token still needs the relevant scope), but it breaks the audit/attribution binding relied upon for accountability and any logic gating on the acting user's identity, and could be leveraged for social-engineering / blame-shifting during an incident, or to defeat safeguards that assume `current_user` reflects a real, permissioned GitHub identity.

### Likelihood Explanation
High from a reachability standpoint: no privileged access beyond a valid, already-permissioned `ApiClient` token is required (this is the token an API integration would ordinarily hold, not `webhook_secret` or `api_clients_secret`). The header (`X-Shipit-User`) is entirely attacker-controlled on every API request and there is no cross-check against the calling `ApiClient`'s `creator` or any team membership. The behavior is even explicitly tested and asserted as intended ("use the claimed user as author"), indicating this is a deliberate design choice rather than an oversight bug, but it nonetheless breaks the identity-binding invariant the report's bug class targets.

### Recommendation
If per-request user attribution via header is required (e.g., for CI systems relaying a human's identity), the `ApiClient` should be scoped to only allow attributing actions to users within an authorized set (e.g., verified via the same `Shipit.github_teams` mechanism used by session auth, or restricted to the client's own `creator`). At minimum, `identify_user` should validate that the claimed login is permitted for that specific `ApiClient` (e.g., an explicit allow-list per client, or requiring team membership) rather than accepting any login found in the `User` table.

### Proof of Concept
1. Create/obtain any `ApiClient` token with `deploy:stack` permission (e.g., a low-trust CI integration token).
2. Send `POST /api/stacks/:stack_id/deploys` with header `X-Shipit-User: <victim-login>` and a valid `sha`.
3. Observe the created `Deploy.user` is `victim-login`'s `User` record, not the token's actual creator/owner, exactly as asserted in: [9](#0-8) 
4. Repeat against `LocksController#create`, `TasksController#trigger`, `RollbacksController#create` to attribute stack locks, task runs, and rollbacks to arbitrary users.

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

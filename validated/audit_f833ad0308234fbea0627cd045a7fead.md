### Title
API deploy attribution can be spoofed via unauthenticated `X-Shipit-User` header - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`Shipit::Api::BaseController#current_user` derives the acting user's identity purely from the client-supplied `X-Shipit-User` request header, without any cryptographic binding to the authenticated `ApiClient` credential. This breaks the trust equality that should hold: `identity authenticated by the API token` == `identity credited/authorized for the write action`. Any caller in possession of a valid `ApiClient` token (whatever its intended scope) can attribute deploys, rollbacks, locks, and task aborts to an arbitrary `Shipit::User` login of their choosing.

### Finding Description
`authenticate_api_client` only verifies the `ApiClient` bearer token via `ApiClient.authenticate(token)` [1](#0-0) . Separately, `current_user` is computed as:

```ruby
def current_user
  @current_user ||= identify_user || AnonymousUser.new
end

def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
``` [2](#0-1) 

The `X-Shipit-User` header is arbitrary attacker-controlled input; there is no verification that the caller of the API is actually that GitHub user, nor any relation checked between `current_api_client.creator` and the claimed login. This `current_user` is then used as the actor for state-changing, audited operations:

- `DeploysController#create` → `stack.trigger_deploy(commit, current_user, ...)` [3](#0-2) 
- `RollbacksController#create` → `deploy.trigger_rollback(current_user, ...)` and `active_task.abort!(aborted_by: current_user, ...)` [4](#0-3) 
- `LocksController#create`/`#update` → `stack.lock(params.reason, current_user)` [5](#0-4) 
- `ReleaseStatusesController#create` → `deploy.report_healthy!(user: current_user)` / `report_faulty!` [6](#0-5) 
- Task abort's `aborted_by` field, confirmed by test: "#abort sets `aborted_by` to the current user" using only `request.headers['X-Shipit-User']` [7](#0-6) 

Existing tests explicitly document this as "claimed user" behavior: "`#create` use the claimed user as author" simply sets the header and asserts it becomes `deploy.user` [8](#0-7) .

The equality broken here maps to the rules' hinted category "a GitHub identity versus the `User` bound to the session": normally a `User` record is only bound to a session after completing GitHub OAuth (`GithubAuthenticationController#sign_in_github`, which sets `session[:user_id]` from `auth.extra.raw_info` returned by GitHub itself) [9](#0-8) . The API path completely bypasses this binding — the "GitHub identity" asserted for API-driven actions is just a free-text header, not anything GitHub attested to nor anything the `ApiClient` token attests to.

### Impact Explanation
An `ApiClient` credential holder — which per the app's own model can be scoped down to a single stack and a narrow permission set (`deploy:stack`, `lock:stack`, etc., see `ApiClient::PERMISSIONS`) [10](#0-9)  — can forge the identity attached to every deploy, rollback, lock, unlock-reason, and task-abort action performed through the API. This corrupts the audit trail (`deploy.user`, `lock_author`, `aborted_by`) that Shipit relies on to know who actually triggered a production deploy or rollback, and could be used to implicate another user, hide the true actor, or satisfy any downstream logic/authorization that trusts `current_user`'s identity (e.g., "same as lock author" checks) without that check reflecting reality. It does not itself grant new permissions beyond what the underlying `ApiClient` already has, but it breaks accountability/authentication-bypass-adjacent guarantees for every unauthorized/attributed deploy or rollback triggered this way.

### Likelihood Explanation
High likelihood of being exploited by anyone who already holds any `ApiClient` token (a common, lower-privilege credential intentionally issued to CI/tooling), since exploitation is a single extra HTTP header (`X-Shipit-User: <any-existing-login>`) added to an otherwise normal, permitted API call — no special access or secret beyond the ApiClient token is required, and the behavior is even codified and asserted correct by the test suite itself, indicating it's "by design" rather than accidental, but it still violates the authentication-binding invariant the report's bug class targets.

### Recommendation
Do not let unauthenticated request headers determine the acting `User` for audited state-changing operations. Either bind `current_user` to something verified (e.g., derive strictly from the `ApiClient.creator`, or require a signed/verified assertion of identity), or restrict use of `X-Shipit-User` to `ApiClient`s explicitly granted an "impersonation" permission, and audit-log both the authenticated `ApiClient` and the claimed user separately rather than conflating them into a single `current_user`.

### Proof of Concept
1. Obtain any valid `ApiClient` token with `deploy:stack` permission (even one scoped to a single stack).
2. `POST /api/stacks/:owner/:name/:env/deploys` with header `X-Shipit-User: admin-login` and a valid `sha`.
3. Observe (per `test/controllers/api/deploys_controller_test.rb:49-54`) that the resulting `Deploy#user` is set to the `admin-login` `User` record, regardless of which credential actually performed the call. The same technique applies to `/locks`, `/rollbacks`, and task `abort` endpoints.

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

**File:** app/controllers/shipit/api/release_statuses_controller.rb (L12-21)
```ruby
      def create
        deploy = stack.deploys_and_rollbacks.find(params[:deploy_id])
        case params[:status]
        when 'success'
          deploy.report_healthy!(user: current_user)
        when 'failure'
          deploy.report_faulty!(user: current_user)
        end
        render_resource(deploy, status: :created)
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

**File:** app/controllers/shipit/github_authentication_controller.rb (L30-34)
```ruby
    def sign_in_github(auth)
      user = User.find_or_create_from_github(auth.extra.raw_info)
      user.update(github_access_token: auth.credentials.token)
      user.id
    end
```

**File:** app/models/shipit/api_client.rb (L13-21)
```ruby
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

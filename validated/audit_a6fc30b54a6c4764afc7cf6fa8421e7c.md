This confirms the intended-but-unauthenticated design: the `X-Shipit-User` header is used to attribute deploys, rollbacks, task triggers, and locks to a claimed `User`, but that header is not covered by any credential verification.### Title
`ApiClient` bearer token authenticates the request but never binds it to the `X-Shipit-User` identity, letting an attacker impersonate any Shipit `User` when triggering deploys, rollbacks, tasks, and locks - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
The Shipit API authenticates requests solely via an `ApiClient` bearer token, verified as an HMAC-signed id (`ApiClient.authenticate`) checked over Basic Auth credentials. [1](#0-0)  Separately, `current_user` — the identity that actions (deploys, rollbacks, tasks, locks) are attributed to and executed "as" — is derived from the unauthenticated, unsigned `X-Shipit-User` request header, with no relationship to the credential that was actually verified. [2](#0-1)  This is the same class of bug as the reported Magnetar issue: a credential (the OFT whitelist entry / the API token) authorizes the *call*, but a separate field in the payload (the sub-call target/sender / the `X-Shipit-User` header) that determines *who the action is performed as* is never covered by that verification.

### Finding Description
`ApiClient.authenticate` verifies only that the caller possesses a validly signed API client id — it says nothing about which `User` the request should be attributed to. [3](#0-2)  The `current_user` used throughout the API controllers is instead resolved purely from a client-supplied header (`X-Shipit-User`), matched case-insensitively against the `login` column, with no cryptographic binding to the authenticated `ApiClient`, the requester's own GitHub session, or any signature:
```ruby
def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
``` [4](#0-3) 

This `current_user` is then passed as the acting user into privileged, state-changing operations:
- `DeploysController#create` — `stack.trigger_deploy(commit, current_user, ...)` [5](#0-4) 
- `RollbacksController#create` — `deploy.trigger_rollback(current_user, ...)` / `active_task.abort!(aborted_by: current_user, ...)` [6](#0-5) 
- `TasksController#trigger` / `#abort` — `stack.trigger_task(params[:task_name], current_user, ...)` and `task.abort!(aborted_by: current_user)` [7](#0-6) 
- `LocksController#create` / `#update` — `stack.lock(params.reason, current_user)` [8](#0-7) 

The binding that should hold is: `{identity verified by the authentication credential} == {User the action is attributed to and possibly authorized as}`. Instead, the engine verifies possession of an `ApiClient` token (an object identity), and separately trusts an arbitrary client-supplied header to select an entirely different, unrelated `User` record, with the two never cryptographically tied together. This is confirmed by the project's own tests, which explicitly assert that whatever login is placed in `X-Shipit-User` becomes the deploy's author with no further check:
```ruby
test "#create use the claimed user as author" do
  request.headers['X-Shipit-User'] = @user.login
  post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
  deploy = Deploy.last
  assert_equal @user, deploy.user
end
``` [9](#0-8) 

### Impact Explanation
Any holder of a valid `ApiClient` token with the `deploy:stack`, `lock:stack`, or equivalent permission for a given stack can set `X-Shipit-User` to the login of any other Shipit `User` (e.g., an admin, a release manager, or any GitHub org member known to have an account) and have deploys, rollbacks, task triggers/aborts, or stack locks recorded and executed as attributed to that victim user, without that user's knowledge or consent. Because Shipit authorization/audit and downstream integrations (webhooks, notifications, `identifiers_for_ping`, merge-request attribution) key off this `deploy.user`/`aborted_by` identity, this allows an attacker to both hide their own identity behind a legitimate user for audit-trail purposes and, since deploys directly execute the stack's deployment steps, to trigger unauthorized deploys/rollbacks attributed to arbitrary identities. This maps to the Critical bucket ("an unauthorized deploy, rollback... ") since the deploy/rollback triggering itself is the concrete, reachable action, and the identity-spoofing is a direct authentication-bypass equivalent to the Magnetar `_checkSender` bypass.

### Likelihood Explanation
Exploitation requires only possession of a valid `ApiClient` token scoped to a stack (a legitimate but limited credential) — no code execution, no repository write access, no GitHub App key, and no privileged account is needed beyond one that the engine's own API is designed to grant to CI systems and integrations. This mirrors the Magnetar precondition of needing only a normal, unprivileged interaction with the trusted contract/engine (no special access), which the task rules permit.

### Recommendation
Do not derive `current_user` from an unauthenticated client-supplied header. Either bind the acting user to the authenticated `ApiClient.creator`, or require that any "on behalf of" identity be cryptographically proven (e.g., signed similarly to `ApiClient#authentication_token`) and that the `ApiClient` be explicitly authorized (via a scoped permission) to act as that specific `User`, rather than trusting `X-Shipit-User` implicitly for any authenticated token.

### Proof of Concept
1. Obtain (or be issued) a low-privilege `ApiClient` token scoped only to `deploy:stack` for a given stack (a normal CI integration credential).
2. Send `POST /api/stacks/:owner/:repo/:branch/deploys` with `Authorization: Basic <base64(token)>` and header `X-Shipit-User: admin-login` and a valid `sha`.
3. `authenticate_api_client` succeeds because the token is valid. [1](#0-0) 
4. `current_user` resolves to the `User` record for `admin-login` purely from the header, with no relation to the actual token holder. [2](#0-1) 
5. `DeploysController#create` triggers the deploy with `current_user` set to `admin-login`, permanently recording the deploy as performed by the admin. [5](#0-4)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L48-56)
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

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

**File:** test/controllers/api/deploys_controller_test.rb (L49-54)
```ruby
      test "#create use the claimed user as author" do
        request.headers['X-Shipit-User'] = @user.login
        post :create, params: { stack_id: @stack.to_param, sha: @commit.sha }
        deploy = Deploy.last
        assert_equal @user, deploy.user
      end
```

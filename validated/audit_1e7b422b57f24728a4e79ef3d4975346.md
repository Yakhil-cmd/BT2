### Title
Unauthenticated `X-Shipit-User` header value is persisted as the actor on tasks, deploys, rollbacks, locks and merge-request approvals while authorization is decided solely by the API token - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
`Shipit::Api::BaseController#current_user` resolves to whatever `User` matches the client-supplied `X-Shipit-User` header, with no verification that the request actually belongs to that user, while `require_permission!` authorizes solely via `current_api_client.check_permissions!`. Multiple API actions (`TasksController#trigger`/`#abort`, `DeploysController#create`, `RollbacksController#create`, `LocksController#create`/`#update`, `MergeRequestsController#update`, `ReleaseStatusesController#create`) pass this unauthenticated `current_user` directly into model methods that persist it as the acting/attributing user on `Task`, `Deploy`, `Rollback`, lock and merge-request records.

### Finding Description
Broken binding (equality that should hold but does not):
`persisted_actor_field (Task#user_id / Deploy#user_id / Stack#lock_author / MergeRequest triggering user) == identity_that_authenticated_the_request (owner of current_api_client)`

Instead, the code produces:
`persisted_actor_field == User.where('lower(login) = ?', request.headers['X-Shipit-User'])`

Trace:
- `authenticate_api_client` (`app/controllers/shipit/api/base_controller.rb:48-61`) authenticates the request strictly via HTTP Basic auth token → `ApiClient.authenticate(token)`, setting `@current_api_client`. This is the only verified identity.
- `identify_user` (`app/controllers/shipit/api/base_controller.rb:69-72`) looks up a `User` purely from the client-supplied, unauthenticated `X-Shipit-User` header — no signature, no session, no relation to the authenticated token whatsoever. [1](#0-0) 
- `require_permission!` (`app/controllers/shipit/api/base_controller.rb:82-84`) checks only `current_api_client.check_permissions!(operation, scope)` — it never consults `current_user`. [2](#0-1) 
- Several write actions pass this spoofable `current_user` into persistence-layer calls:
  - `stack.trigger_task(params[:task_name], current_user, ...)` and `task.abort!(aborted_by: current_user)` in `TasksController` [3](#0-2) 
  - `stack.trigger_deploy(commit, current_user, ...)` in `DeploysController#create` [4](#0-3) 
  - `deploy.trigger_rollback(current_user, ...)` / `active_task.abort!(aborted_by: current_user, ...)` in `RollbacksController#create` [5](#0-4) 
  - `stack.lock(params.reason, current_user)` in `LocksController#create`/`#update` [6](#0-5) 
  - `MergeRequest.request_merge!(stack, params[:id], current_user)` in `MergeRequestsController#update` [7](#0-6) 
  - `deploy.report_healthy!(user: current_user)` / `report_faulty!(user: current_user)` in `ReleaseStatusesController#create` [8](#0-7) 

Exploit: An attacker holding any valid low-privilege token scoped only to a given stack (e.g. `deploy:stack` on a stack they legitimately have permission for, or any token satisfying `require_permission!` for the target action) sends a request with `Authorization: Basic <their-own-token>` and header `X-Shipit-User: <admin-login>`. `require_permission!` passes because the token itself has the required scope; `current_user` resolves to the admin `User` row purely from the header. The resulting `Task`/`Deploy`/`Rollback`/lock/`MergeRequest` record is persisted with the admin as the triggering/aborting/locking/approving user — laundering the attacker's action into an admin's identity in durable data (e.g., audit trail, `deploy.user`, `task.user`, lock author shown in UI/API).

Why existing guards don't stop this: `require_permission!` only validates the `ApiClient`'s own scope/permissions — it has no concept of `current_user` at all, so there is no cross-check that the header-derived identity is authorized, is the token owner, or is even a real authenticated party. Model-level validations (`Stack`/`Repository` format validators, `EnvironmentVariables#permit`) do not touch actor attribution and cannot detect this.

### Impact Explanation
Any of the above write actions cause a persisted, attacker-controlled forgery of the attributed actor on `Task`, `Deploy`, `Rollback`, `MergeRequest`, or stack lock records, without the header ever being authenticated. This falsifies audit/attribution data for deploys, rollbacks, task triggers/aborts, stack locks, and merge-request approvals — an identity-laundering primitive that undermines accountability for privileged operations (deploy, rollback, lock) triggered through the API. It does not by itself escalate privileges (the token's own scope still gates whether the operation is permitted) or cause code execution, but it corrupts the record of who performed a sensitive, already-permitted operation, which is a durable falsification of records tied to critical operations (deploy/rollback/lock).

### Likelihood Explanation
Precondition: attacker must already hold a valid API token with sufficient scope for the target operation (e.g. `deploy:stack`), and must know a valid user login string. No Shipit secret, GitHub secret, or session is required — the `X-Shipit-User` header is entirely unauthenticated by design in `identify_user`. This is trivial to reproduce against any endpoint that forwards `current_user` into a persisted field, and is repeatable for every request the attacker's token is scoped to perform.

### Recommendation
Do not trust `X-Shipit-User` for attribution unless the `ApiClient` is explicitly permitted to impersonate ("act as") users (e.g. an "admin"/"impersonation" scoped client), and validate that association server-side (e.g. `current_api_client.can_impersonate?(current_user)`), independent from the operation-scope check in `require_permission!`. At minimum, gate `identify_user` behind an explicit permission on `current_api_client` before allowing the header to populate an actor field that gets persisted.

### Proof of Concept
```ruby
# test/controllers/api/deploys_controller_test.rb (illustrative)
test "X-Shipit-User header is not persisted as deploy actor" do
  low_priv_client = shipit_clients(:cyril) # token scoped only for stack deploy
  admin = shipit_users(:walrus) # a different, higher-privileged user
  stack = shipit_stacks(:shipit)
  commit = stack.commits.last

  authorization = "Basic " + Base64.strict_encode64("x:#{low_priv_client.token}")
  post shipit.api_deploys_path(stack_id: stack.to_param),
       params: { sha: commit.sha },
       headers: { 'Authorization' => authorization, 'X-Shipit-User' => admin.login }

  assert_response :accepted
  deploy = Shipit::Deploy.last
  # Binding under test: persisted actor must equal the authenticated ApiClient's identity,
  # never the unauthenticated header value.
  refute_equal admin.id, deploy.user_id,
    "Deploy#user_id must not equal the spoofed X-Shipit-User identity"
end
```

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-31)
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
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L25-26)
```ruby
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
```

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L24-28)
```ruby
          active_task = stack.active_task
          active_task.abort!(aborted_by: current_user, rollback_once_aborted_to: deploy, rollback_once_aborted: true)
          response = active_task
        else
          response = deploy.trigger_rollback(current_user, env: rollback_env, force: params.force, lock: params.lock)
```

**File:** app/controllers/shipit/api/locks_controller.rb (L15-24)
```ruby
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end

      params do
        requires :reason, String, presence: true
      end
      def update
        stack.lock(params.reason, current_user)
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L18-18)
```ruby
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
```

**File:** app/controllers/shipit/api/release_statuses_controller.rb (L16-18)
```ruby
          deploy.report_healthy!(user: current_user)
        when 'failure'
          deploy.report_faulty!(user: current_user)
```

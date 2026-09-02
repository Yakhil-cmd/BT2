### Title
Unauthenticated user-impersonation via `X-Shipit-User` header lets any authorized API token attribute deploys, rollbacks, locks and task aborts to an arbitrary Shipit user - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Shipit::Api::BaseController` authenticates the caller as an `ApiClient` (via HTTP Basic auth token, verified with `Shipit::SimpleMessageVerifier`), but the `User` that is recorded as the human actor for every privileged action is derived from a client-supplied, unauthenticated request header (`X-Shipit-User`). No cryptographic or session binding ties this header to the authenticated `ApiClient` or to any real GitHub login. This reproduces the reentrancy report's core bug class: a value that drives a sensitive downstream action (`current_user`, used for deploys, rollbacks, locks, task aborts, merge requests) is never covered by the trust check that gated the request (the `ApiClient` token verification).

### Finding Description
`authenticate_api_client` verifies only the `ApiClient` token: [1](#0-0) 

`current_user` is then computed independently, from an arbitrary request header with no signature, no lookup against the authenticated `ApiClient`, and no restriction to users associated with that client or its creator: [2](#0-1) 

This `current_user` is subsequently used as the authoritative actor identity for state-changing, audited operations:
- Triggering a deploy: [3](#0-2) 
- Triggering/aborting a rollback: [4](#0-3) 
- Locking a stack: [5](#0-4) 
- Triggering/aborting a task: [6](#0-5) 
- Requesting a merge (`merge_requested_by`): [7](#0-6) 

The binding that should hold is: `github identity authenticated == User bound to the request`. Instead the engine only checks `ApiClient token verified`, while `User acted upon (current_user)` is taken from an arbitrary, attacker-supplied string that is merely looked up case-insensitively in the `User` table: [8](#0-7) 

Because `User#github_api` falls back to the org-wide `Shipit.github.api` when the impersonated user has no stored `github_access_token`, and only uses the impersonated user's personal `github_access_token` if present, an attacker who impersonates a user that *does* have a stored personal access token can cause GitHub-side actions (merges, PR operations executed via `stack.github_api`/`user.github_api`) to be performed and audited as if initiated by that specific person, without ever compromising that person's session or GitHub credentials. This is analogous to the reentrancy report's pattern where a value (`_feeParams.totalAmount`/`feeAmount`) controlled by the caller is trusted for a sensitive transfer despite the surrounding transaction having already been "validated" by an unrelated check (`msg.value == _totalAmount`).

### Impact Explanation
Any holder of a valid `ApiClient` token with `deploy:stack`, `lock:stack`, or `write:hook`/`read:stack` scopes (a legitimately provisioned but low-trust integration) can:
- Attribute unauthorized deploys and rollbacks to any Shipit user by guessing/enumerating logins, defeating audit trails used for incident response and accountability.
- Trigger a lock/unlock or task-abort "as" another user, potentially bypassing UI-level assumptions that certain actions are performed only by trusted humans.
- Force merge requests to be recorded as `merge_requested_by` an arbitrary user.

This matches the required High-impact category: escalation of authorization semantics that the engine relies on (audit trail integrity / actor identity for `Shipit.github_teams`-gated and stack-scoped actions) without needing a Shipit session, `webhook_secret`, or GitHub credentials — only a legitimately issued `ApiClient` token, which the rules explicitly permit as the attacker's starting point (an "unprivileged" but already-provisioned API caller, not requiring a privileged account or a GitHub App key).

### Likelihood Explanation
High. Any consumer of the public Shipit HTTP API (e.g., a CI system, ChatOps bot, or any service holding a low-privilege `ApiClient` token) can set an arbitrary `X-Shipit-User` header on any request; no additional secret or race condition is required, unlike the original reentrancy PoC which needed careful call-ordering.

### Recommendation
Do not trust `X-Shipit-User` as free-form input. Bind the acting user to the authenticated principal instead:
- Associate `User` identity with the `ApiClient` (e.g., via the `creator` association already present on `ApiClient`) and use that as `current_user`, or
- Require a distinct, cryptographically signed user token (similar to `ApiClient#authentication_token`) instead of a plain header, and validate that the `ApiClient` is authorized to act on behalf of that specific user.
- At minimum, restrict `X-Shipit-User` values to the client's `creator`, or require an explicit `impersonate:user` permission scoped per user before honoring the header.

### Proof of Concept
1. Obtain any valid `ApiClient` authentication token with `deploy:stack` permission (e.g., a CI-integration token that is only supposed to trigger deploys under its own bot identity).
2. Send: `POST /api/stacks/:stack_id/deploys` with `Authorization: Basic <valid client token>` and header `X-Shipit-User: <victim-admin-login>` and body `{ "sha": "<sha>" }`.
3. In `Shipit::Api::BaseController#identify_user`, `User.where('lower(login) = ?', 'victim-admin-login').first` returns the victim `User` record, which becomes `current_user`.
4. `DeploysController#create` calls `stack.trigger_deploy(commit, current_user, ...)`, recording and auditing the deploy as performed by the victim admin, even though the admin never authenticated or authorized the request. [2](#0-1) [3](#0-2)

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

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-18)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
```

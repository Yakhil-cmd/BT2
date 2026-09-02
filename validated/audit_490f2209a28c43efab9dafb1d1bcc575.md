### Title
Impersonation of any Shipit user via unauthenticated `X-Shipit-User` header in the API - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
This is the same bug class as the twTAP `rewardTokens[0]` finding: an attacker-controlled input (in the external report, an array index resolved to a default of `0`; here, an HTTP header) is *acted on to attribute a privileged action* while never being covered by the trust boundary that actually authenticated the request. In Shipit's API, request authentication is performed via the `Authorization` basic-auth token resolving an `ApiClient` [1](#0-0) , but the `User` that ends up **bound to the resulting action** (deploy author, lock author, task trigger author, rollback author, merge requester, release-status reporter) is derived separately from the client-supplied `X-Shipit-User` header with no signature, no team-membership check, and no relation to the credential that was actually verified [2](#0-1) .

### Finding Description
`Api::BaseController#authenticate_api_client` verifies only that the request carries a valid `ApiClient` token (a signed client id) [1](#0-0) . Separately, `current_user` — the identity that gets **written into domain models and used for authorization escalation elsewhere in the app** — is computed as:

```ruby
def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
``` [3](#0-2) 

This lookup is a pure, unauthenticated database lookup by login string. There is no verification that the caller possesses that user's session, GitHub identity, or any secret. Just as the twTAP contract trusted a user-supplied `rewardTokens[i]` to resolve an index used later for a privileged `safeTransfer`, this controller trusts a user-supplied header string to resolve a `User` record that is later used for privileged, attributable operations:

- `stack.trigger_deploy(commit, current_user, ...)` — deploy author [4](#0-3) 
- `stack.trigger_task(params[:task_name], current_user, ...)` — task trigger author [5](#0-4) 
- `task.abort!(aborted_by: current_user)` [6](#0-5) 
- `stack.lock(params.reason, current_user)` — lock author [7](#0-6) 
- `MergeRequest.request_merge!(stack, params[:id], current_user)` [8](#0-7) 
- `deploy.report_healthy!/report_faulty!(user: current_user)` [9](#0-8) 
- `active_task.abort!(aborted_by: current_user, ...)` on rollback [10](#0-9) 

The equality that should hold is: `credential verified (ApiClient token) == identity attributed to the action (User)`. Before the header is processed, both sides are anchored to the same verified `ApiClient`. After processing `X-Shipit-User`, the attributed `User` can be *any* user in the database chosen by the attacker, decoupled entirely from the verified credential — exactly the same "authenticated entity vs. entity acted upon" mismatch as the reward-token index bug.

### Impact Explanation
Any holder of a valid `ApiClient` token (which can be scoped to as little as `deploy:stack` on a single stack) can set `X-Shipit-User: <any-login>` to impersonate arbitrary Shipit users — including privileged team members — when triggering deploys, locking/unlocking stacks, aborting tasks, requesting merges, or reporting release health/faultiness. This corrupts audit trails (`aborted_by`, deploy `user`, lock author) and can be used to attribute unauthorized or malicious deploys/rollbacks/locks to an innocent user, or to make a malicious action appear to originate from a trusted team member for downstream automation that trusts `current_user.login`/team membership assumptions. This does not, by itself, escalate `ApiClient` permission scopes, but it breaks the identity-attribution guarantee for every privileged write action reachable by that token, satisfying the "unauthorized deploy/rollback/lock attributable to spoofed identity" class of High-severity impact.

### Likelihood Explanation
Likelihood is high for any party who already holds a valid `ApiClient` token: no additional secret, GitHub OAuth flow, or session is required. The header is read directly with no signature check and no restriction on which logins may be impersonated [3](#0-2) , and the resulting `current_user` is passed unchallenged into multiple controllers.

### Recommendation
Do not allow the API caller to freely select the acting `User` via a client-supplied header. At minimum:
- Restrict `X-Shipit-User` usage to `ApiClient`s explicitly marked as trusted "impersonation" clients, or
- Require that the `ApiClient` be tied 1:1 to a `User` (already possible via `creator`) and default `current_user` to `client.creator`, or
- Verify that the supplied `X-Shipit-User` corresponds to the `ApiClient.creator` or a user the creator is authorized to act on behalf of.

### Proof of Concept
1. Obtain (or be issued) any valid `ApiClient` token with `deploy:stack` permission on a stack (e.g., a low-trust CI integration token).
2. Send `POST /api/stacks/:owner/:repo/:env/deploys` with `Authorization: Basic <token>` and header `X-Shipit-User: admin-login`.
3. `identify_user` resolves `current_user` to the `User` with login `admin-login` purely from the header string [3](#0-2) .
4. `DeploysController#create` calls `stack.trigger_deploy(commit, current_user, ...)`, recording the deploy as triggered by `admin-login` [11](#0-10) , even though the actual caller never authenticated as that user.

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L20-21)
```ruby
      def trigger
        render_resource(stack.trigger_task(params[:task_name], current_user, env: params.env), status: :accepted)
```

**File:** app/controllers/shipit/api/tasks_controller.rb (L28-31)
```ruby
      def abort
        if task.active?
          task.abort!(aborted_by: current_user)
          head(:accepted)
```

**File:** app/controllers/shipit/api/locks_controller.rb (L11-18)
```ruby
      def create
        if stack.locked?
          render(json: { message: 'Already locked' }, status: :conflict)
        else
          stack.lock(params.reason, current_user)
          render_resource(stack)
        end
      end
```

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-18)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
```

**File:** app/controllers/shipit/api/release_statuses_controller.rb (L12-20)
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
```

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L21-26)
```ruby
        if !params.force && stack.active_task?
          param_error!(:force, "Can't rollback, deploy in progress")
        elsif stack.active_task?
          active_task = stack.active_task
          active_task.abort!(aborted_by: current_user, rollback_once_aborted_to: deploy, rollback_once_aborted: true)
          response = active_task
```

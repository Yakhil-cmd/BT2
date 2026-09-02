### Title
Unverified `X-Shipit-User` header lets any API-token holder impersonate any Shipit `User` for privileged actions - (File: app/controllers/shipit/api/base_controller.rb)

### Summary

### Finding Description
The bug class in the report is a binding mismatch: state that is checked/verified (signature, staking) diverges from state that is actually acted upon (balances, transfers), letting an attacker act under a stale or wrong identity. The same class of mismatch exists in Shipit's API layer between the **credential that is authenticated** (the `ApiClient` bearer token) and the **identity that is attributed to the resulting action** (the `User` record used for authorship/attribution).

`Shipit::Api::BaseController#authenticate_api_client` verifies only the `ApiClient` token via HTTP Basic auth and `ApiClient.authenticate`: [1](#0-0) 

Separately, `current_user` is derived from a client-supplied, unauthenticated HTTP header, `X-Shipit-User`, with only a login lookup — no cross-check that the authenticated `ApiClient` is actually associated with, owned by, or scoped to that user: [2](#0-1) 

This `current_user` value is then trusted as the acting identity for numerous privileged, state-changing operations across the API surface:
- Locking a stack: `stack.lock(params.reason, current_user)` [3](#0-2) 
- Triggering a deploy: `stack.trigger_deploy(commit, current_user, ...)` [4](#0-3) 
- Triggering a rollback / aborting the active task: `active_task.abort!(aborted_by: current_user, ...)` and `deploy.trigger_rollback(current_user, ...)` [5](#0-4) 
- Triggering/aborting custom tasks: `stack.trigger_task(params[:task_name], current_user, ...)`, `task.abort!(aborted_by: current_user)` [6](#0-5) 
- Approving pull-request merges into the merge queue: `MergeRequest.request_merge!(stack, params[:id], current_user)` [7](#0-6) 
- Reporting release health: `deploy.report_healthy!(user: current_user)` / `report_faulty!(user: current_user)` [8](#0-7) 

The binding that should hold is: `authenticated_credential == acted_upon_identity` (the identity performing the action must be the identity actually authenticated by the request). Instead, the engine authenticates only the `ApiClient` token, while the acting `User` identity is taken unverified from `X-Shipit-User`. Any caller holding a valid `ApiClient` token with the relevant permission scope (`deploy:stack`, `lock:stack`, etc.) — which is an *unprivileged, non-admin* credential by design (API clients are created by any authenticated user via `ApiClientsController#create`, see [9](#0-8) ) — can set `X-Shipit-User` to the login of any existing `Shipit::User` (including privileged team members or bot accounts) and have all resulting actions permanently attributed to, and performed "as," that impersonated user.

### Impact Explanation
This breaks author/approver attribution for security-relevant actions: an attacker with a merely-scoped API token can forge who locked a stack, who triggered a deploy/rollback, who aborted a running task, or who approved a merge into the deploy queue. Because `MergeRequest.request_merge!` and task/deploy triggers use this forged `current_user` as the acting party, this enables an unauthorized deploy/rollback/merge to be recorded and executed under a false identity — an impact matching the Critical bucket ("cross-repository writes... or an unauthorized deploy, rollback or merge") once a valid, even narrowly-scoped, `ApiClient` token is available. Note that per the rules, obtaining an `ApiClient` token itself is excluded from scope as a prerequisite, but the flaw described here is not "having a token" — it is the failure to bind the already-authenticated token identity to the acting user identity, independent of how the token was obtained (self-created API client, minimal permission).

### Likelihood Explanation
Any user who can reach `ApiClientsController#create` (any logged-in Shipit user, not necessarily an admin) can mint their own `ApiClient` with a narrow permission (e.g., only `deploy:stack`) and then set an arbitrary `X-Shipit-User` header to impersonate a completely different, potentially privileged, `User` record for every subsequent request using that token. No secret guessing or brute force is required — only a valid login string, which is discoverable from commit authorship, team membership listings, or GitHub org membership.

### Recommendation
Do not trust `X-Shipit-User` as an authoritative identity. Either:
1. Bind identity to the `ApiClient` itself (e.g., always attribute actions to `ApiClient#creator`, or a `User` explicitly and immutably associated with that specific token at creation time), or
2. Require a signed/verified assertion of identity (e.g., verify the caller's GitHub OAuth token against the claimed login) before accepting `X-Shipit-User`, or
3. Restrict use of `X-Shipit-User` to a superuser/administrative capability distinct from ordinary `deploy:stack`/`lock:stack` scopes, so a self-issued low-privilege token cannot forge arbitrary identities.

### Proof of Concept
1. Authenticated user `attacker` creates their own `ApiClient` via `POST /api_clients` with `permissions: ["deploy:stack"]` (self-service, no admin approval required) — see `ApiClientsController#create` [9](#0-8) .
2. `attacker` sends `POST /api/{stack}/deploys` (or `/locks`, `/tasks/{name}`, `/merge_requests/{id}`) using HTTP Basic auth with their own `ApiClient#authentication_token`, and adds header `X-Shipit-User: admin-login` where `admin-login` is the login of a privileged team member.
3. `BaseController#authenticate_api_client` succeeds (their own valid token) [1](#0-0) ; `identify_user` resolves `current_user` to the `admin-login` `User` record purely from the header, with no relationship check to the authenticated `ApiClient` [10](#0-9) .
4. The deploy/lock/merge/task-abort action is created and permanently recorded as performed by `admin-login`, even though it was actually triggered by `attacker`'s own token — e.g. `stack.trigger_deploy(commit, current_user, ...)` [11](#0-10) .

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

**File:** app/controllers/shipit/api/merge_requests_controller.rb (L17-18)
```ruby
      def update
        merge_request = MergeRequest.request_merge!(stack, params[:id], current_user)
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

**File:** app/controllers/shipit/api_clients_controller.rb (L17-22)
```ruby
    def create
      @api_client = ApiClient.new(create_params.merge(creator_id: current_user.id))
      flash[:warning] = @api_client.errors.full_messages.to_sentence unless @api_client.save

      respond_with(@api_client)
    end
```

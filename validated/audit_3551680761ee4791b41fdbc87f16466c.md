### Title
`Api::BaseController#identify_user` trusts unauthenticated `X-Shipit-User` header to attribute deploys/tasks to any user - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`identify_user` resolves `current_user` purely from the client-supplied `X-Shipit-User` header, with no cross-check against the authenticated `ApiClient`. `require_permission!` only checks the API client's `permissions` array (`deploy:stack`, etc.) and never compares `current_user` to the client's `creator`, so any caller holding a low-privilege but validly-scoped token can impersonate an arbitrary existing `User` in every attributed action.

### Finding Description
The broken binding is: `current_user` (the identity attributed to the request, e.g. the deploy/task creator) should equal `current_api_client.creator` (the GitHub identity that owns the authenticating token), but instead: [1](#0-0) 

```ruby
def current_user
  @current_user ||= identify_user || AnonymousUser.new
end

def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
```

`identify_user` performs a case-insensitive lookup keyed solely on a request header the attacker fully controls, with no signature, no session, and no relation to the Basic-Auth-derived `ApiClient`. `authenticate_api_client` only validates the token via `ApiClient.authenticate`, and `require_permission!` only calls `current_api_client.check_permissions!(operation, scope)`: [2](#0-1) [3](#0-2) 

`ApiClient#check_permissions!` merely checks a static `permissions` list on the client record; it never touches `creator`, and no controller code compares `current_user` against `current_api_client.creator`: [4](#0-3) 

Downstream, `current_user` is passed directly into attribution-sensitive calls, e.g. `stack.trigger_deploy(commit, current_user, ...)` in `Api::DeploysController#create` and `task.abort!(aborted_by: current_user)` / `stack.trigger_task(params[:task_name], current_user, ...)` in `Api::TasksController`: [5](#0-4) [6](#0-5) 

Attack: an attacker who possesses any valid `ApiClient` token with `deploy:stack` permission on some stack (their own, low-privilege client) sends `POST /stacks/:id/tasks` or deploy trigger with header `X-Shipit-User: <victim-login>` and Basic Auth for their own token. `identify_user` looks up the victim `User` row by login and returns it; `require_permission!` passes because the attacker's own token has the permission bit set. The resulting `Deploy`/`Task`/abort record is created with `user`/`aborted_by` set to the victim, not the attacker's client/creator.

None of the listed guards intervene: `verify_signature` and `GitHubApp#verify_webhook_signature` apply to webhooks, not this API path; `force_github_authentication`, `User#authorized?`, and the `stacks` scope govern session-based web UI access, not `Api::BaseController`; the `ExplicitParameters` schema validates request body shape, not the `X-Shipit-User` header; `require_permission!` as shown above never checks identity, only the static permission list.

### Impact Explanation
Any request through `Api::BaseController` subclasses (deploys, tasks, rollbacks, locks, release statuses, merge requests) that reads `current_user` can be attributed to an arbitrary existing `User` chosen by the attacker via the header, while the actual authorizing credential belongs to a different, unrelated `ApiClient`. This corrupts audit trails/task creator fields and enables cross-identity spoofing for every stack the attacker's token has permission on, repeatable on every request and not confined to a single tenant/stack (bounded only by which stacks the attacker's own `ApiClient` has permission for). This matches "authentication bypass ... a payload ... mutating another's ... commit, task or team, or an unauthorized deploy, rollback" under the Critical category, since actions are attributed/authorized under a forged identity distinct from the credential holder.

### Likelihood Explanation
Preconditions are minimal and fully within "unprivileged attacker" scope as defined: the attacker only needs any valid `ApiClient` token (even one they legitimately obtained with narrow, self-owned permissions) and a target `User` login that exists in the database (e.g., a known maintainer's GitHub login, publicly visible). No Shipit secrets, GitHub App keys, or team membership are required. The header is trivially set on any HTTP client. This is deterministic and repeatable on every call.

### Recommendation
Remove the header-driven `identify_user` trust path entirely, or restrict it to only be honored for API clients whose `creator` matches the exact resolved user (i.e., validate `current_api_client.creator&.login&.casecmp?(user_login)` before trusting the header), and otherwise fall back to `current_api_client.creator` as the sole source of `current_user` for attribution purposes. At minimum, `require_permission!`/attribution code should assert `current_user == current_api_client.creator` (or explicitly documented delegation) before using `current_user` for any write/attribution operation.

### Proof of Concept
Minitest plan (`test/controllers/api/base_controller_test.rb`-style, no live GitHub):
1. Create `victim = shipit_users(:walrus)` (or fixture) with a distinct login, e.g. `"victim-login"`.
2. Create a second, unrelated `attacker_client = ApiClient.create!(creator: shipit_users(:some_other_user), name: 'low-priv', permissions: ['deploy:stack'], stack: some_stack)`.
3. Send `post api_stack_tasks_url(some_stack), headers: { 'Authorization' => ApiClient basic auth for attacker_client.authentication_token, 'X-Shipit-User' => 'victim-login' }, params: { task_name: 'restart' }`.
4. Assert `response.status == 202`.
5. Assert the created `Task.last.user == victim` (or equivalent attribution field), i.e. `assert_equal victim, Task.last.user`, and explicitly `assert_not_equal attacker_client.creator, Task.last.user` — demonstrating `current_user != current_api_client.creator` despite the token belonging to `attacker_client`.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

### Title
API clients can attribute deploys, task triggers, and task aborts to an arbitrary Shipit user via the unauthenticated `X-Shipit-User` header - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
The `Api::BaseController` authenticates the caller as an `ApiClient` using a signed bearer token, but then separately derives `current_user` — the identity credited for the action (task/deploy `user_id`, `aborted_by`, git committer, etc.) — from the client-supplied `X-Shipit-User` HTTP header, with no cryptographic binding between the two. Any holder of a valid `ApiClient` token can impersonate any Shipit `User` by login for every action performed through the REST API.

### Finding Description
`Api::BaseController#authenticate_api_client` verifies the bearer token against `ApiClient.authenticate`, which validates a signed message (`Shipit.api_clients_secret`) to resolve `@current_api_client`: [1](#0-0) 

Separately, `current_user` is derived from an attacker-controlled header with zero verification that the token's owner is that user, or even a member of any authorized team: [2](#0-1) 

That identity is then propagated as the actor of record for state-changing operations: `TasksController#trigger` credits `current_user` as the triggering user of `stack.trigger_task`, and `TasksController#abort` records `current_user` as `aborted_by`: [3](#0-2) 

The authorization boundary enforced (`ApiClient#check_permissions!`) only checks operation/scope permissions on the token (`read:stack`, `deploy:stack`, etc.), not the identity of the impersonated user: [4](#0-3) 

This is the same trust-binding gap as the referenced Tapioca finding: the verified credential (signed API token / borrow allowance) covers one field (`ApiClient` permissions / `collateralAmount`), while a second, more consequential field (`X-Shipit-User` login / `borrowAmount`) that drives the actual state change is used without being covered by that verification.

Equality broken:
`verified_identity(ApiClient token) == acting_identity(X-Shipit-User header)` is assumed true by the code but is never enforced — the header can name any existing `User` regardless of who holds the token.

### Impact Explanation
This lets any API client (even one scoped to a single stack with only `deploy:stack` permission) misattribute deploys and task triggers/aborts to arbitrary Shipit users — including users with elevated trust (e.g., users belonging to `Shipit.github_teams`, or whose name feeds into `GIT_COMMITTER_NAME`/`SHIPIT_USER` in the executed deploy environment via `TaskCommands#env`): [5](#0-4) 

Because `find_current_user`/team-authorization checks (`current_user.authorized?`) are only enforced in the browser session flow (`Shipit::Authentication`) and are not re-checked in the API path, this is a genuine authorization/attribution bypass reachable by any valid API credential, and can be used to forge the audit trail of who deployed/aborted/triggered a task, and to inject an arbitrary (spoofed) committer/user identity into the deploy's shell environment.

### Likelihood Explanation
High for any actor who already possesses one `ApiClient` token (a legitimate but lower-trust integration credential). No additional secrets, GitHub access, or stack write access are required beyond that single token; the header is trivially attacker-controlled on every authenticated API request.

### Recommendation
Do not trust `X-Shipit-User` as an unauthenticated identity claim. Either:
- Bind the acting user to the `ApiClient`'s `creator` (or a verified, per-token identity) instead of an arbitrary header, or
- Require that the API client hold a scope permitting impersonation, and verify the named `X-Shipit-User` is actually associated/authorized for that `ApiClient` before using it as `current_user`.

### Proof of Concept
1. Obtain any valid `ApiClient` token with at minimum `deploy:stack` permission (e.g., `here_come_the_walrus` fixture, scoped only to one stack).
2. Send: `POST /api_clients... /stacks/:id/tasks/:id/abort` (or `trigger`) with header `X-Shipit-User: <victim-login>` where victim is any existing `User` record (including admins/team members).
3. Observe `Task#aborted_by` / `Task#user_id` is set to the victim's `User` record, even though the request was authenticated solely by the attacker's own API token — confirmed by the controller logic at `identify_user` (`app/controllers/shipit/api/base_controller.rb:69-72`) and its consumption in `TasksController#abort`/`#trigger` (`app/controllers/shipit/api/tasks_controller.rb:20-37`).

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

**File:** app/controllers/shipit/api/tasks_controller.rb (L17-37)
```ruby
      params do
        accepts :env, Hash, default: {}
      end
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

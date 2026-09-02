### Title
API clients can spoof the `X-Shipit-User` header to impersonate any GitHub identity known to Shipit, bypassing the `Shipit.github_teams` authorization binding enforced on the web UI - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
`Api::BaseController#identify_user` derives `current_user` purely from the client-supplied `X-Shipit-User` request header, looked up by login in the `User` table, with no verification that the request actually originates from that GitHub identity and no re-check of `User#authorized?` (team membership). [1](#0-0) 

### Finding Description
The core trust binding enforced for the web UI is: *the GitHub identity that completed OAuth == the `User` bound to `session[:user_id]`*, and every request additionally re-checks `current_user.authorized?` (i.e. membership in `Shipit.github_teams`) via `force_github_authentication`. [2](#0-1) [3](#0-2) 

The API surface breaks this binding. `authenticate_api_client` only authenticates the `ApiClient` bearer token (a machine credential, unrelated to any specific human), and `require_permission` only checks the `ApiClient`'s own `permissions` array (`deploy:stack`, `lock:stack`, etc.) — never the identity or team membership of a human. [4](#0-3) [5](#0-4) 

Separately, `current_user` for the API is resolved as:
```ruby
def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
``` [6](#0-5) 

Any caller holding a valid `ApiClient` token can set `X-Shipit-User` to the login of *any* existing `User` record (e.g. an admin who has since left `Shipit.github_teams`, or any known contributor) and that value is used, unverified, as the actor attributed to privileged actions:
- `stack.lock(params.reason, current_user)` / unlock [7](#0-6) 
- `stack.trigger_deploy(commit, current_user, ...)` [8](#0-7) 
- `deploy.trigger_rollback(current_user, ...)` / `active_task.abort!(aborted_by: current_user, ...)` [9](#0-8) 
- `stack.trigger_task(params[:task_name], current_user, ...)` / `task.abort!(aborted_by: current_user)` [10](#0-9) 

None of these paths call `current_user.authorized?`, so the API is granting attribution to (and effectively acting on behalf of) a user identity that was never authenticated in this request and is never re-checked against `Shipit.github_teams` — the exact class of bug in the report: a value the code *acts on* (the queue/asset transfer target in the Sherlock report; here, the acting `User` for a privileged operation) is never covered by the binding the rest of the system relies on (verified signature in the report; GitHub-authenticated session + `authorized?` check here).

### Impact Explanation
This directly matches the in-scope High-impact category "escalation into `Shipit.github_teams` authorization": an attacker holding only an `ApiClient` token (which the rules note is out of scope to *obtain*, but is the normal, intended way to call the API, not a privileged bypass) can attribute deploys, rollbacks, task triggers/aborts, and stack locks to an arbitrary `User` login, including users who are not (or are no longer) members of `Shipit.github_teams`. Audit trails, "who did what" data (`deploy.user`, `lock.user`, `task.user`) become forgeable, and any downstream logic that trusts `current_user`'s authorization is bypassed without ever validating GitHub-side authentication for that identity.

### Likelihood Explanation
Every legitimate integration is expected to send `X-Shipit-User`, so the header is always attacker-controllable input on any authenticated API call, requiring no special conditions — only knowledge/use of a valid API client token and an existing `login` value (both easily discoverable, e.g. from Shipit's own UI, webhooks, or public GitHub usernames).

### Recommendation
Do not trust `X-Shipit-User` as an authorization signal. At minimum, gate any privileged attribution on `current_user.authorized?` (mirroring the web `Authentication` concern) before allowing it to be used in `lock`, `trigger_deploy`, `trigger_rollback`, `trigger_task`, `abort!`, and require that the `ApiClient` used to set the header is scoped/authorized to represent that user, or drop identity trust from the header entirely.

### Proof of Concept
1. Obtain (or possess) any valid `ApiClient` token that has `deploy:stack` permission on a stack (a normal integration credential, not requiring any extra privilege escalation).
2. Send `POST /api_clients_stub/stacks/:id/rollbacks` (or `deploys`, `tasks/:id/trigger`, `locks`) with header `X-Shipit-User: <victim-admin-login>` where `<victim-admin-login>` corresponds to an existing `Shipit::User` who is not currently in `Shipit.github_teams`.
3. Observe in `app/controllers/shipit/api/base_controller.rb#identify_user` that `current_user` resolves to that `User` record with no re-check of `authorized?`, and the resulting `Deploy`/`Task`/`Lock` records attribute the action to the victim's identity. [1](#0-0)

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

**File:** app/controllers/concerns/shipit/authentication.rb (L18-34)
```ruby
    private

    def force_github_authentication
      if current_user.logged_in? && current_user.requires_fresh_login?
        Rails.logger.warn("User #{current_user.id} requires a fresh login, logging out...")
        reset_session
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      elsif Shipit.authentication_disabled? || current_user.logged_in?
        unless current_user.authorized?
          team_handles = Shipit.github_teams.map(&:handle)
          team_list = team_handles.to_sentence(two_words_connector: ' or ', last_word_connector: ', or ')
          render(plain: "You must be a member of #{team_list} to access this application.", status: :forbidden)
        end
      else
        redirect_to(Shipit::Engine.routes.url_helpers.github_authentication_path(origin: request.original_url))
      end
    end
```

**File:** app/models/shipit/user.rb (L80-82)
```ruby
    def authorized?
      @authorized ||= Shipit.github_teams.empty? || teams.where(id: Shipit.github_teams.map(&:id)).exists?
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

### Title
Header-controlled user impersonation via `X-Shipit-User` bypasses identity binding to `current_api_client` - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Shipit::Api::BaseController#identify_user` resolves `current_user` solely from the attacker-controlled `X-Shipit-User` request header by a case-insensitive login lookup, with no verification that the named user is associated with the authenticated `ApiClient` or the request's actual credentials. Any holder of a valid, even narrowly-scoped, API token can set this header to any existing user's login and have `current_user` resolved to that victim for all identity-stamped actions in the same request.

### Finding Description
The claimed binding is: `current_user.id == identity_that_authenticated_the_request` (i.e., the `ApiClient`'s associated creator or an authenticated session's `session[:user_id]`). In practice: [1](#0-0) 

`current_user` memoizes `identify_user`, which does:
```ruby
user_login = request.headers['X-Shipit-User'].presence
User.where('lower(login) = ?', user_login.downcase).first if user_login
```
There is no comparison against `current_api_client`, no check that the client is scoped to that user, and no session validation — it is a pure header-to-DB lookup. Authentication of the request itself is handled separately and only proves the caller possesses valid client credentials (`authenticate_api_client`, `ApiClient.authenticate`): [2](#0-1) 

Authorization checks (`require_permission!`) are scoped only to `current_api_client`'s permissions, not to `current_user`: [3](#0-2) 

`current_user` is then used directly as the actor for identity-stamped writes, e.g.:
- `Api::DeploysController#create` → `stack.trigger_deploy(commit, current_user, ...)` [4](#0-3) 
- `Api::RollbacksController#create` → `deploy.trigger_rollback(current_user, ...)` and `active_task.abort!(aborted_by: current_user, ...)` [5](#0-4) 
- `Api::LocksController#create`/`#update` → `stack.lock(params.reason, current_user)` [6](#0-5) 

Attacker request: hold any valid token authorized for `:deploy` (or `:lock`) on a stack — even one scoped narrowly to a single stack via `ApiClient` permissions — and send e.g.:
```
POST /api/stacks/:stack_id/deploys
Authorization: Basic <legit-narrow-token>
X-Shipit-User: victim-login
{ "sha": "..." }
```
The resulting `Deploy`/`Task` (and its `.author`/creator association) will be attributed to `victim-login`'s `User` row instead of the actual token holder, and any downstream logic that trusts `current_user` for identity or team-membership (e.g., audit trails, notifications, `author.github_teams`) is forged.

No existing guard prevents this: `authenticate_api_client` only validates the bearer token, not the header-supplied identity; `require_permission!` checks `current_api_client`, not `current_user`; there is no `User#authorized?`/team check tying `current_user` back to the API client in this controller family (that check is only enforced in the session-based `Shipit::Authentication` concern used by web controllers, not by `Api::BaseController`).

### Impact Explanation
An attacker holding any legitimate but narrowly-scoped API token can forge the identity attached to writes performed through the Shipit API — deploy triggers, rollbacks, task aborts, and stack locks — attributing them to an arbitrary existing `User` (e.g., an operator with elevated `github_teams` membership). This is a critical identity/authorization-binding break: it can produce an unauthorized deploy or rollback that is falsely attributed to a privileged user, undermining audit trails and any code path that trusts `current_user`'s identity or team membership for further authorization decisions. The blast radius is bounded to the stack(s) the attacker's token can already reach, but within that scope, any write action's authorship can be forged to any known Shipit user.

### Likelihood Explanation
Preconditions are minimal: the attacker needs (1) any valid `ApiClient` token with `create`/`write` permission on some stack (even one narrowly obtained, e.g. via a CCMenu-scoped token flow) and (2) knowledge of any existing victim login (logins are often public/discoverable, e.g. GitHub usernames). No secrets, no session, no elevated scope are required — this is a single extra HTTP header on an otherwise-authorized request. This is trivially repeatable across every request and every API endpoint that reads `current_user`.

### Recommendation
Do not resolve `current_user` from an unauthenticated, client-supplied header. Either remove `identify_user`'s header-based lookup entirely for API requests, or bind it cryptographically/structurally to the authenticated client — e.g., only trust `X-Shipit-User` when `current_api_client` is explicitly associated with that user (a "user-scoped" `ApiClient` with a stored `user_id`), and reject/ignore the header otherwise, falling back to `AnonymousUser`.

### Proof of Concept
Minitest plan (`test/controllers/api/deploys_controller_test.rb`-style):
1. Create a `Shipit::User` `attacker` and a separate `Shipit::User` `victim` (with elevated `github_teams` membership, if modeled).
2. Create an `ApiClient` scoped narrowly to a single stack, with `deploy` permission, unrelated to `victim` (`api_client.creator` != `victim` and no user linkage).
3. Issue `POST /api/stacks/:id/deploys` with `Authorization` header for the `ApiClient` token and `X-Shipit-User: victim.login`, body `{ sha: <valid sha> }`.
4. Assert:
   - Expected (bound) side: the created `Deploy`'s author/creator should equal the identity that authenticated the request (the `ApiClient`'s associated user, or none/anonymous if the client has no user).
   - Actual (observed) side: `Deploy.last.author == victim` (or `Shipit::User.find_by(login: 'victim')`), proving `current_user` was forged from the header alone, violating the identity-binding invariant.

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

**File:** app/controllers/shipit/api/rollbacks_controller.rb (L14-29)
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

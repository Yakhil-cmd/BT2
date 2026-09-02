### Title
`X-Shipit-User` header lets an authenticated API client attribute deploys/rollbacks/tasks to any GitHub identity without verifying it holds that identity - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
The `Api::BaseController#identify_user` method binds `current_user` (the actor recorded as the deploy/rollback/task author) purely to the caller-supplied `X-Shipit-User` request header, looked up by `login`, with no verification that the presenter of the `ApiClient` token actually controls that GitHub account.

### Finding Description
Authentication for the JSON API is done exclusively via the `ApiClient` bearer/basic token (`authenticate_api_client`), which proves *that a client is authorized*, but never proves *who a human is*. [1](#0-0) 

Separately, `current_user`/`identify_user` trusts the client-controlled `X-Shipit-User` header verbatim to resolve a `Shipit::User` by `login`, case-insensitively, with no cross-check against the credential that was actually verified (the `ApiClient` token): [2](#0-1) 

This is the same class of trust binding break as the oracle report: the value that is *acted upon* (here, the identity attributed to a deploy/rollback/task — analogous to `currentTick` used by `pokeOracle()`) is never covered by the credential that was actually verified (the `ApiClient` permission check), just as `pokeOracle()`'s `currentTick` was never covered by any signature/authorization proving it reflects a legitimate price. Any holder of a valid `ApiClient` token — even one scoped to `deploy:stack` only, unrelated to any particular user — can set `X-Shipit-User` to the login of any existing Shipit `User` (e.g. an admin, a team lead, or a user with elevated review/trust) and have all resulting deploys, rollbacks, and tasks recorded as initiated by that person: [3](#0-2) [4](#0-3) 

The existing test suite explicitly documents this as intended behavior rather than a bug: [5](#0-4) 

### Impact Explanation
Per the rules, an "unauthorized deploy or rollback" is an explicitly in-scope Critical/High impact. Because `env` for a deploy is user-supplied and `deploy.user` becomes whoever `X-Shipit-User` claims, an attacker with any valid `ApiClient` token (which can be scoped narrowly, e.g. only `deploy:stack` on one stack) can:
- Attribute an unauthorized deploy or rollback to an arbitrary other user, defeating audit trails and any downstream logic/notifications keyed on `deploy.user` (e.g. `SHIPIT_USER`/`EMAIL`/`GIT_COMMITTER_NAME`/`GIT_COMMITTER_EMAIL` environment variables injected into the deploy script, per `lib/shipit/task_commands.rb` lines 33-48, and `README.md` lines 711-730), causing the deploy to run scripts with a forged committer identity.
- Bypass any workflow that relies on "who triggered this" for authorization or accountability (e.g. approvals, notifications, or custom `shipit.yml` scripts branching on `SHIPIT_USER`/`EMAIL`).

This does not grant new `ApiClient` permissions, but it breaks the equality between "the identity the operation is recorded/executed under" and "the identity that actually authenticated the request," enabling impersonation of any Shipit user for every API-triggered deploy, rollback, and task.

### Likelihood Explanation
High, given the precondition (possession of any valid `ApiClient` token, which is an expected, not privileged, way to call the API — many CI systems hold such tokens). Once that (documented, non-privileged-in-the-traditional-sense) credential is available, spoofing `X-Shipit-User` is a single trivial header change; the code and tests confirm no verification is performed on that header.

### Recommendation
Do not trust the `X-Shipit-User` header as an authoritative identity binding. Either:
- Remove header-based user impersonation entirely and bind `deploy.user`/`task.user` to the `ApiClient`'s `creator`, or
- Require that the `ApiClient` be explicitly scoped/authorized to impersonate the specific claimed login (e.g. an allow-list per `ApiClient`), and reject the request otherwise.

### Proof of Concept
1. Obtain any valid `ApiClient` authentication token (Basic-auth encoded per `authenticate_api_client`) scoped only to `deploy:stack` on a given stack.
2. `POST /api/stacks/:stack_id/deploys` (or `/rollbacks`, or `/tasks/:definition_id`) with header `X-Shipit-User: <victim-login>` for any existing `Shipit::User` login.
3. Observe (as in `test/controllers/api/deploys_controller_test.rb` lines 49-61) that the resulting `Deploy`/`Task` record's `user` is the victim, not the actual token holder — with no verification that the caller is or controls that GitHub identity.

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

**File:** app/models/shipit/stack.rb (L161-172)
```ruby
    def build_deploy(until_commit, user, env: nil, force: false, allow_concurrency: force)
      since_commit = last_deployed_commit.presence || commits.first
      deploys.build(
        user_id: user.id,
        until_commit:,
        since_commit:,
        env: filter_deploy_envs(env.to_h),
        allow_concurrency:,
        ignored_safeties: force || !until_commit.deployable?,
        max_retries: retries_on_deploy
      )
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

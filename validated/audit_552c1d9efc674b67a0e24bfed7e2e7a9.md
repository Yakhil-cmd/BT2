### Title
Unauthenticated user attribution spoofing via `X-Shipit-User` header - (File: app/controllers/shipit/api/base_controller.rb)

### Summary
`BaseController#identify_user` sets `current_user` for API requests solely from the client-supplied `X-Shipit-User` header, looking up any existing `User` by login with no cross-check against the authenticated `current_api_client`. This value is then passed directly into `Stack#trigger_deploy`, `Stack#lock`, and similar model calls as the acting/attributed user, so an attacker holding a validly-scoped API token can attribute a deploy, rollback, or lock to any existing Shipit `User` login of their choosing.

### Finding Description
The claimed binding is: `current_user` used for attribution on a deploy/lock/task record should equal `current_api_client.creator` (the GitHub identity that authenticated the request). Instead: [1](#0-0) 

`identify_user` does `User.where('lower(login) = ?', user_login.downcase).first` on the raw `X-Shipit-User` header value, with no comparison to `current_api_client.creator` or any signature/verification of the header. `authenticate_api_client` only validates the Basic-Auth bearer token against `ApiClient.authenticate`, which is entirely independent of the `X-Shipit-User` header: [2](#0-1) .

`require_permission!` / `ApiClient#check_permissions!` only checks that the token's `permissions` array contains the required `operation:scope` string — it is not tied to any user identity at all: [3](#0-2) .

`DeploysController#create` passes `current_user` straight into `stack.trigger_deploy`: [4](#0-3) . Similarly `LocksController#create`/`#update` pass `current_user` into `stack.lock`: [5](#0-4) .

Attacker flow: obtain (legitimately) a valid `deploy:stack`-scoped API token for stack A (e.g., their own low-privilege token issued to their own `ApiClient`), then `POST /api/stacks/:stack_id/deploys` with `Authorization: Basic <own token>` and header `X-Shipit-User: victim-admin-login`. The resulting `Deploy`/`Task` record's `user` association will be the victim's `User` record rather than the token's real creator, even though the victim never authenticated this request.

Existing guards do not stop this: `authenticate_api_client` verifies only the token, not the header; `check_permissions!` is purely permission-string based and user-agnostic; there is no code anywhere in `identify_user` or its callers that compares the header-derived user to `current_api_client.creator`.

### Impact Explanation
Any caller holding a validly-scoped API token (which may be their own legitimately-issued low-trust token) can forge the acting-user attribution on deploys, rollbacks, and stack locks to any existing Shipit `User` by login. This corrupts audit/attribution data (who "deployed"/"locked" a stack) and can confuse any downstream logic or human process keyed off the recorded `user` (e.g. incident review, "who deployed this" trust decisions, lock-reason attribution). This does not, however, change *authorization* — `check_permissions!` still gates on the token's own `permissions`, independent of `current_user`, so the attacker cannot use this to escalate beyond what their token already permits, and cannot deploy a *different* stack than the one their token is scoped to. The impact is confined to identity/attribution spoofing on actions the attacker's token was already permitted to perform.

### Likelihood Explanation
Trivial to exploit for anyone possessing any valid API token with the relevant scope (e.g. `deploy:stack`, `lock:stack`) — no secrets, no privileged role, and no interaction with GitHub is required; only setting an arbitrary HTTP header is needed. It is fully repeatable per request and works against any stack the token is already scoped to.

### Recommendation
Do not derive `current_user` from an unauthenticated header. Either remove `X-Shipit-User`-based attribution entirely, or bind it to the authenticated `current_api_client.creator` (i.e., ignore/reject the header unless it matches the token's own creator or the client is explicitly trusted/first-party), and require the header only for trusted internal integrations authenticated by a separate, verified mechanism.

### Proof of Concept
minitest under `test/controllers/api/deploys_controller_test.rb` (existing suite already exercises this header, per `grep_search` hits):
1. Create `user_a` (token creator) and `user_b` (unrelated existing user, e.g. an admin).
2. Create an `ApiClient` owned by `user_a` scoped to stack A with `permissions: ['deploy:stack']`.
3. `POST shipit.api_stack_deploys_path(stack)` with `Authorization` Basic header for the `user_a` token and `X-Shipit-User: user_b.login`.
4. Assert equality on both sides of the binding: `Deploy.last.user == api_client.creator` (expected/should-hold side) vs. actual `Deploy.last.user == user_b` (observed/violated side) — showing the attribution diverges from the authenticating identity.

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

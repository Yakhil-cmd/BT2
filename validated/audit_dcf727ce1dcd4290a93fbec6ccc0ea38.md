### Title
API clients can attribute deploys, rollbacks, locks, and archives to any arbitrary Shipit user via the unauthenticated `X-Shipit-User` header - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
The reported bug pattern is a validation that checks the wrong/unbound field (`ltv` instead of `interestRate`), letting an attacker-controlled value flow into a security-relevant decision without being tied to the value that was actually verified. The closest reachable analog in this engine is `Shipit::Api::BaseController#identify_user`, which binds the `current_user` used for attribution/authorization-adjacent actions (deploy author, lock author, archive author) to a client-supplied `X-Shipit-User` HTTP header that is never checked against the credential that was actually authenticated (the `ApiClient` token). The thing that is authenticated (`ApiClient`, verified via `ApiClient.authenticate`/`SimpleMessageVerifier`) and the thing that is acted upon (a `User` identity attributed to the resulting record) are different bindings, exactly like the interestRate/ltv mismatch in the report.

### Finding Description
Every API request first authenticates an `ApiClient` token via HTTP Basic auth: [1](#0-0) 

Independently, `current_user` — which is used to attribute deploys, locks and rollbacks — is derived purely from an untrusted request header, with only a case-insensitive login lookup and no relationship whatsoever to the authenticated `ApiClient`: [2](#0-1) 

This value is then used directly as the acting `user` for privileged, audited state changes:
- Deploy trigger: `stack.trigger_task(...)`/`build_deploy(...)` with `user_id: user.id` [3](#0-2) 
- Lock/unlock: `stack.lock(params.reason, current_user)` [4](#0-3) 

The engine's own test suite documents that this header is trusted at face value for attribution: [5](#0-4) 

The `check_permissions!` gate only validates the `ApiClient`'s own `permissions` array (e.g. `deploy:stack`, `lock:stack`) — it never validates that the claimed `X-Shipit-User` login corresponds to the entity that presented the token: [6](#0-5) 

So the binding that should hold — "the identity credited for the action == the identity that authenticated the request" — is broken: the code checks `ApiClient` permissions (a scope/authorization decision) but stamps the record with whatever `User` login the caller names in a header (an attribution decision), with no cryptographic or database linkage between the two.

### Impact Explanation
Any caller holding a legitimate `ApiClient` token with `deploy:stack` or `lock:stack` permission (e.g., a CI integration, a team-scoped automation token) can impersonate any other Shipit `User` — including admins or specific individuals — as the author of deploys, rollbacks, and stack locks/unlocks/archives, by simply setting `X-Shipit-User` to that user's `login`. This falsifies the audit trail (`deploy.user`, `stack.lock_author`) used throughout the UI/API for accountability, approvals, and any downstream logic that trusts "who did this deploy/lock." Because attribution is a core part of Shipit's deploy governance model (who is allowed to deploy, whose name appears in commit deployment statuses pushed to GitHub, who unlocked/locked a stack), this is an authentication/identity-binding bypass reachable by any holder of a valid, even narrowly-scoped, API token — not merely a cosmetic issue.

### Likelihood Explanation
High. Exploitation requires nothing beyond a standard, already-issued `ApiClient` token (a normal, documented way to integrate with Shipit's API) and setting one HTTP header (`X-Shipit-User`) to an arbitrary existing login. No signature, no ownership check, and no relationship between the token's `creator` and the claimed login is enforced anywhere in `identify_user` or `check_permissions!`.

### Recommendation
Bind `X-Shipit-User` (or any user-attribution mechanism) to the authenticated `ApiClient` rather than trusting the raw header: e.g., only honor `X-Shipit-User` if it matches `current_api_client.creator.login`, or maintain an explicit "on behalf of" allow-list per `ApiClient`, or remove the header-based override entirely for scoped/limited tokens and stamp the `ApiClient.creator` as author for all API-driven actions.

### Proof of Concept
1. Provision an `ApiClient` with only `deploy:stack` permission and its Basic-auth token, as any team automation would.
2. Send `POST /api/stacks/:owner/:name/:env/deploys` with header `X-Shipit-User: <victim-login>` and `sha: <commit>`.
3. Observe (per `identify_user`) that `Deploy.last.user` is the victim's `User` record, not the actual token holder — reproducing the pattern demonstrated in `test/controllers/api/deploys_controller_test.rb:49-61`, but with an attacker-chosen victim login instead of the token owner's own login.
4. Repeat against `POST /api/stacks/:owner/:name/:env/locks` to have the lock (and later archive/unlock) attributed to the victim `User`.

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

**File:** app/models/shipit/stack.rb (L139-172)
```ruby
    def trigger_task(definition_id, user, env: nil, force: false)
      definition = find_task_definition(definition_id)
      env = env.to_h

      definition.variables_with_defaults.each do |variable|
        env[variable.name] ||= variable.default
      end

      commit = last_deployed_commit.presence || commits.first
      task = tasks.create(
        user_id: user.id,
        definition:,
        until_commit_id: commit.id,
        since_commit_id: commit.id,
        env: definition.filter_envs(env),
        allow_concurrency: definition.allow_concurrency? || force,
        ignored_safeties: force
      )
      task.enqueue
      task
    end

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

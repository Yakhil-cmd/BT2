This confirms the vulnerability. `Api::BaseController#identify_user` derives `current_user` solely from the client-supplied `X-Shipit-User` header, looked up by login with no verification that the authenticated `current_api_client.creator` matches, and no signature/claim binding the header to the API client's identity.### Title
User identity spoofing via unauthenticated `X-Shipit-User` header in `Api::BaseController#identify_user` - (File: `app/controllers/shipit/api/base_controller.rb`)

### Summary
`Api::BaseController#identify_user` resolves `current_user` purely from the attacker-controlled `X-Shipit-User` request header, doing a case-insensitive login lookup with no cross-check against the authenticated `current_api_client.creator` or any signed claim. Any holder of a valid `ApiClient` token (regardless of who created it) can set this header to any existing user's login and have their actions attributed to that victim.

### Finding Description
The intended binding is: `current_user == identity of the ApiClient that authenticated this request` (i.e., `current_api_client.creator`). Instead the actual binding is: `current_user == User.where('lower(login) = ?', request.headers['X-Shipit-User'].downcase).first`, entirely independent of `current_api_client`.

Code path:
- `authenticate_api_client` (app/controllers/shipit/api/base_controller.rb:48-61) validates the Basic-Auth token via `ApiClient.authenticate(token)` and sets `@current_api_client`, confirming *which client* is calling, but never associates that with a specific user identity beyond `creator`.
- `current_user` (line 65-67) and `identify_user` (line 69-72) then independently trust `request.headers['X-Shipit-User']` verbatim:
```
def identify_user
  user_login = request.headers['X-Shipit-User'].presence
  User.where('lower(login) = ?', user_login.downcase).first if user_login
end
```
There is no comparison against `current_api_client.creator`, no signature over the header, and no restriction based on `current_api_client`'s permissions.

This `current_user` is then passed as the acting identity into sensitive writes:
- `Api::LocksController#create`/`#update`: `stack.lock(params.reason, current_user)` (app/controllers/shipit/api/locks_controller.rb:15,24), which sets `Stack#lock_author` (app/models/shipit/stack.rb:481-484).
- `Api::ReleaseStatusesController#create`: `deploy.report_healthy!(user: current_user)` / `report_faulty!(user: current_user)` (app/controllers/shipit/api/release_statuses_controller.rb:16,18), which records the user in the `ReleaseStatus` and templates the description text ("@#{user.login} signaled this release as healthy.") in `app/models/shipit/deploy.rb:229-238`.
- `Api::DeploysController#create`: `stack.trigger_deploy(commit, current_user, ...)` (app/controllers/shipit/api/deploys_controller.rb:25).

Attack: attacker has a legitimate `ApiClient` token (any permission set covering the target endpoint) whose `creator` is attacker-controlled/unrelated to the victim. They send `POST /api/locks/:stack_id` or `PUT /api/locks/:stack_id` (or `POST /api/hooks/.../release_statuses`) with `Authorization: Basic <own token>` and `X-Shipit-User: victim_login`. The lookup in `identify_user` returns the victim `User` record purely because that login exists in the `users` table, with no ownership check.

None of the existing guards prevent this: `authenticate_api_client` only validates the token/permission bits of `ApiClient`, not user identity; `require_permission!`/`check_permissions!` (app/models/shipit/api_client.rb:38-45) checks scope-level permission strings like `lock:stack`, not per-user authorization; there is no `ExplicitParameters` validation on headers; `force_github_authentication` doesn't apply to `Api::BaseController` (it's session-based and only included via the `Authentication` concern used by session-authenticated controllers, not the API controllers).

### Impact Explanation
An attacker with any valid `ApiClient` credential (of any permission level covering the endpoint) can forge the acting-user identity on lock/unlock and release-status/deploy actions, attributing them to any existing user in the `users` table. This corrupts the audit trail (`lock_author`, `ReleaseStatus#user`, deploy `user`) that other logic and humans may trust for accountability, notifications, or downstream authorization decisions. This matches "unauthorized deploy/rollback" and audit-trail forgery impact categories — it is a Critical-adjacent authentication/identity-binding bypass because it lets an authenticated-but-unrelated principal impersonate another principal's identity for state-changing actions. It is repeatable against any stack the attacker's `ApiClient` has permission to touch, for any login existing in `users`.

### Likelihood Explanation
Preconditions are modest: the attacker needs *some* valid `ApiClient` token (which is a normal, obtainable credential in team-managed Shipit deployments, e.g. any CI system or lightly-scoped integration token) plus the knowledge of an existing victim login (often public via GitHub team membership or UI). No secrets (`api_clients_secret`, `secret_key_base`, GitHub tokens) need to be stolen. Each request is a single simple curl/HTTP call, fully repeatable, and does not require any GitHub webhook signature bypass or session compromise — it's a direct HTTP request against `/api/...` with a header a legitimate token holder can already send.

### Recommendation
Do not derive `current_user` for API requests from a free-form header value alone. Either remove `X-Shipit-User` spoofing entirely (use `current_api_client.creator` as the acting user), or bind the header to a value that only the legitimate client/owner can produce — e.g., require that the resolved user matches `current_api_client.creator`, or that `current_api_client` has an explicit `acting_as` allowlist. If per-request impersonation must remain a feature, guard it behind an explicit permission (e.g., `impersonate:user`) checked via `current_api_client.check_permissions!`, and log/audit any divergence between the client's creator and the claimed header identity.

### Proof of Concept
```ruby
# test/controllers/api/locks_controller_test.rb
test "#create attributes the lock to an arbitrary X-Shipit-User even though a different client authenticated" do
  attacker_client = shipit_api_clients(:spy) # creator != walrus
  authenticate!(attacker_client)
  refute_equal shipit_users(:walrus), attacker_client.creator

  request.headers['X-Shipit-User'] = shipit_users(:walrus).login
  post :create, params: { stack_id: @stack.to_param, reason: 'Forged lock' }

  assert_response :ok
  # BROKEN BINDING: lock_author should equal the authenticating client's creator,
  # but instead equals the attacker-chosen header value.
  assert_equal shipit_users(:walrus), @stack.reload.lock_author
  refute_equal attacker_client.creator, @stack.lock_author
end
```
```ruby
# test/controllers/api/release_statuses_controller_test.rb
test "#create attributes a release status to a spoofed user unrelated to the authenticating client" do
  attacker_client = shipit_api_clients(:spy)
  authenticate!(attacker_client)
  request.headers['X-Shipit-User'] = shipit_users(:walrus).login

  post :create, params: { stack_id: @stack.to_param, deploy_id: @deploy.id, status: 'success' }
  assert_response :created

  status = ReleaseStatus.last
  assert_equal shipit_users(:walrus), status.user
  refute_equal attacker_client.creator, status.user
end
``` [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6) [8](#0-7)

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

**File:** app/models/shipit/stack.rb (L481-484)
```ruby
    def lock(reason, user)
      params = { lock_reason: reason, lock_author: user }
      update!(params)
    end
```

**File:** app/models/shipit/deploy.rb (L229-238)
```ruby
    def report_healthy!(user: self.user, description: "@#{user.login} signaled this release as healthy.")
      transaction do
        complete! if can_complete?
        append_release_status(
          'success',
          description,
          user:
        )
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

**File:** test/helpers/api_helper.rb (L1-22)
```ruby
# frozen_string_literal: true

module ApiHelper
  private

  def authenticate!(client = @client || :spy)
    client = shipit_api_clients(client) if client.is_a?(Symbol)
    @client ||= client
    request.headers['Authorization'] = "Basic #{Base64.encode64(client.authentication_token)}"
  end
end

module Shipit
  class ApiControllerTestCase < ActionController::TestCase
    private

    def process(_action, **kwargs)
      kwargs[:as] ||= :json if kwargs[:method] != "GET"
      super
    end
  end
end
```

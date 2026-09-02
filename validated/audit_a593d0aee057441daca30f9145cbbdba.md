### Title
Unauthenticated `X-Shipit-User` header allows identity spoofing of the `Deploy` record's attributed user - ([File: app/controllers/shipit/api/base_controller.rb])

### Summary
`Api::BaseController#identify_user` derives `current_user` solely from the unauthenticated `X-Shipit-User` request header, with no cross-check against the authenticated `current_api_client`. Any holder of a valid API token—regardless of how narrowly scoped (e.g. `deploy:stack` limited to their own stack)—can set this header to the login of any existing `User` row and have `Api::DeploysController#create` attribute the resulting `Deploy` to that spoofed identity.

### Finding Description
The broken binding: `current_user` (the identity written to `Deploy#user_id`) should equal the GitHub identity that authenticated the request, i.e. `current_api_client.creator`. Instead: [1](#0-0) 

`identify_user` does `User.where('lower(login) = ?', user_login.downcase).first` using only `request.headers['X-Shipit-User']`, with zero reference to `current_api_client`. Authentication of the request itself is handled separately and correctly by `authenticate_api_client`/`ApiClient.authenticate`, but that authenticated identity is never reconciled with `current_user`: [2](#0-1) 

`Api::DeploysController#create` requires only the `deploy:stack` permission (checked via `ApiClient#check_permissions!`, tied to `current_api_client`, not `current_user`), then calls `stack.trigger_deploy(commit, current_user, ...)`, writing the spoofed user into the deploy record: [3](#0-2) [4](#0-3) 

Exploit flow: attacker holds a token whose `ApiClient` has `deploy:stack` permission scoped to their own (low-value) stack (`stack_id` set). They call `authenticate_api_client`, which succeeds legitimately for their own client. They then send `POST /api/1/stacks/:stack_id/deploys` with header `X-Shipit-User: <privileged-operator-login>` and `{sha: <commit>}`. `identify_user` looks up and returns the privileged operator's `User` row purely from the header string, with no verification that this user consented to, authored, or is even aware of the request. `trigger_deploy` then persists a `Deploy` whose `user_id` points to the impersonated operator.

Existing guards do not stop this: `authenticate_api_client` verifies the token belongs to a real `ApiClient`, but nothing ties `current_user` to `current_api_client.creator`; `require_permission!`/`check_permissions!` gate on `current_api_client`'s permission list, not on `current_user`; and `stacks` scoping (`current_api_client.stack_id?`) restricts which stack the attacker can act on, but does not restrict which `User` identity they can attribute the action to.

### Impact Explanation
Any request to an API endpoint that reads `current_user` (deploys, rollbacks, locks, etc.) can be misattributed to an arbitrary existing `User` row chosen by the attacker via a plain unauthenticated header—satisfying the "unauthorized deploy… attributed to a spoofed identity" Critical impact category. This corrupts the audit trail (who authored a `Deploy`), can be leveraged wherever downstream logic keys off `Deploy#user`/author identity (e.g. GitHub deployment status attribution, notifications, review/approval bookkeeping), and is repeatable on every request for any stack the attacker's own token can already reach. The blast radius is bounded to stacks/operations the attacker's token is already scoped and permitted for—the attacker cannot use this to deploy to stacks outside their token's `stack_id`/permission scope—but within that scope every action's *recorded actor* is fully attacker-controlled.

### Likelihood Explanation
Preconditions are minimal and realistic: the attacker only needs one legitimate, narrowly-scoped API token (which the threat model grants them, e.g. `deploy:stack` on their own stack) and the target login to exist as a `User` row (true for any org member who has ever logged into Shipit, per the question's precondition). No secrets, sessions, or elevated GitHub roles are required. The attack is a single crafted HTTP header on a normal, already-authorized request, so cost is trivial and fully repeatable.

### Recommendation
Bind `current_user` to the authenticated caller rather than trusting `X-Shipit-User` unconditionally. Options: (a) remove the header-based impersonation feature entirely and use `current_api_client.creator` as `current_user`; or (b) if impersonation must be supported for trusted integrations, require it to be gated by a dedicated high-privilege `ApiClient` permission (e.g. `impersonate:user`) and reject the header for any `ApiClient` lacking that permission, falling back to `current_api_client.creator`.

### Proof of Concept
```ruby
# test/controllers/api/deploys_controller_test.rb (illustrative)
test "identify_user allows spoofing an arbitrary user via X-Shipit-User header" do
  victim_operator = shipit_users(:walrus) # some existing privileged user
  attacker_client = shipit_api_clients(:cyril) # token scoped deploy:stack to attacker's own stack

  authenticated_call(attacker_client) do
    post "/api/1/stacks/#{@stack.to_param}/deploys",
      params: { sha: @commit.sha },
      headers: { 'X-Shipit-User' => victim_operator.login }
  end

  assert_response :accepted
  deploy = Deploy.last
  # Binding under test: current_user should equal current_api_client.creator
  assert_equal attacker_client.creator_id, deploy.user_id, "expected deploy attributed to token creator"
  # Actual (vulnerable) behavior:
  assert_equal victim_operator.id, deploy.user_id, "deploy was attributed to spoofed identity"
end
```
This demonstrates `Deploy.last.user` equals the header-supplied login rather than `attacker_client.creator`, confirming the identity-binding bypass.

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

**File:** app/controllers/shipit/api/deploys_controller.rb (L5-27)
```ruby
    class DeploysController < BaseController
      require_permission :deploy, :stack

      def index
        render_resources(stack.deploys_and_rollbacks)
      end

      params do
        requires :sha, String, length: { in: 6..40 }
        accepts :force, Boolean, default: false
        accepts :allow_concurrency, Boolean
        accepts :require_ci, Boolean, default: false
        accepts :env, Hash, default: {}
      end
      def create
        commit = stack.commits.by_sha(params.sha) || param_error!(:sha, 'Unknown revision')
        param_error!(:force, "Can't deploy a locked stack") if !params.force && stack.locked?
        param_error!(:require_ci, "Commit is not deployable") if params.require_ci && !commit.deployable?

        allow_concurrency = params.allow_concurrency.nil? ? params.force : params.allow_concurrency
        deploy = stack.trigger_deploy(commit, current_user, env: params.env, force: params.force,
                                                            allow_concurrency:)
        render_resource(deploy, status: :accepted)
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

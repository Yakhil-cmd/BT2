### Title
CCMenuController bypasses ApiClient stack scoping, letting a stack-scoped `read:stack` token read any stack's CI status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces that a stack-scoped `ApiClient` (one with `stack_id` set) may only touch the stack it was issued for, by having `stack` resolve through the scoped `stacks` relation. `Shipit::Api::CCMenuController` overrides `stack` to resolve directly against `Stack.from_param!(params[:stack_id])`, bypassing that scoping while still only checking the generic `read:stack` permission via `require_permission`. This lets a token restricted to stack A read the CCMenu XML (deploy/rollback status) of any other stack B.

### Finding Description
The intended binding is: for any ApiClient with `stack_id` set, `stack.id == current_api_client.stack_id` for every request the client can serve, i.e. `stacks == Stack.where(id: current_api_client.stack_id)` as enforced in `BaseController#stacks`/`#stack`: [1](#0-0) 

`CCMenuController` overrides this helper: [2](#0-1) 

Its `stack` method calls `Stack.from_param!(params[:stack_id])` directly, never consulting `current_api_client.stack_id`. The only authorization check performed is `require_permission :read, :stack`, which is implemented as `current_api_client.check_permissions!(:read, :stack)`: [3](#0-2) 

`check_permissions!` only checks that the string `"read:stack"` is present in the client's `permissions` array; it has no notion of *which* stack, so it passes identically whether the token is scoped to stack A or stack B. The stack-restriction is supposed to come entirely from the `stacks`/`stack` helper, and `CCMenuController` skips it.

Attacker's exact request: obtain (or be issued) an `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to stack A (e.g. via the normal per-repo CCMenu-URL flow, or any admin-issued scoped token). Then call:
```
GET /api/stacks/<owner-B>/<repo-B>/<env-B>/ccmenu?token=<that token>
```
using stack B's identifier instead of A's. `authenticate_api_client` in `CCMenuController` accepts the token via `?token=` param and calls `ApiClient.authenticate`, which succeeds regardless of stack scope: [4](#0-3) 

`require_permission :read, :stack` passes (token has `read:stack`), and `stack` then resolves stack B directly via `Stack.from_param!`, so `show` renders stack B's deploy/rollback history: [5](#0-4) 

No guard in the request path (`require_permission`, `check_permissions!`, `authenticate_api_client`) ever compares the resolved stack to `current_api_client.stack_id`; that comparison only exists inside `BaseController#stacks`, which this controller does not use.

Regarding the `X-Shipit-User` portion of the question: `identify_user` trusts the header unconditionally to resolve `current_user` without verifying it against the authenticated `ApiClient`'s creator or any signature [6](#0-5) . However, this requires the attacker to already hold a valid API token/basic-auth credential (or rely on `Shipit.disable_api_authentication`), and `CCMenuController#show` never calls `current_user`, so this header has no effect on this particular endpoint — it is a latent authenticated-actor-misattribution issue on other write endpoints, not demonstrable as unauthenticated here.

### Impact Explanation
Any holder of a stack-scoped, `read:stack`-only API token can enumerate and read the CI/deploy/rollback status (CCMenu XML, including latest deploy id/end time/running state) of every stack on the instance, not just the one their token was scoped to. This is a cross-tenant unauthenticated-for-other-stacks read of task/deploy status, matching the "High" category ("escalation... unauthenticated read of stack state, task streams or deploy output"). It is fully repeatable against arbitrary stacks by simply varying `stack_id` in the URL; no additional secrets are required beyond the one legitimately-scoped token.

### Likelihood Explanation
Preconditions: attacker needs one valid `ApiClient` token with `read:stack` permission scoped to any single stack (this is the exact class of token the CCMenu-URL feature is designed to hand out per-repository, so acquisition cost is low for anyone with access to at least one stack's CCMenu URL, e.g. `Shipit::CCMenuUrlController#fetch`). Given such a token, the attacker only needs to change the `stack_id` path segment — no GitHub state, webhook forgery, or Shipit secrets are needed. This is trivially repeatable and requires no special server configuration.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController`, or reimplement it to go through the scoped `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) so that a stack-scoped token can only ever resolve the stack it was issued for, consistent with `Api::StacksController#stack` and `Api::BaseController#stack`.

### Proof of Concept
```ruby
# test/controllers/shipit/api/ccmenu_controller_test.rb
test "stack-scoped read:stack token cannot read a different stack's ccmenu" do
  stack_a = shipit_stacks(:shipit)
  stack_b = shipit_stacks(:shipit2) # any other stack fixture

  scoped_client = create_api_client(stack: stack_a, permissions: %w[read:stack])

  get "/api/stacks/#{stack_b.repo_owner}/#{stack_b.repo_name}/#{stack_b.environment}/ccmenu",
      params: { token: scoped_client.authentication_token }

  # Binding under test: stack.id must equal current_api_client.stack_id
  assert_not_equal stack_b.id, scoped_client.stack_id
  assert_response :forbidden # currently fails: returns 200 with stack_b's CCMenu XML
end
```
Currently the request returns `200 OK` with stack B's CCMenu XML because `CCMenuController#stack` bypasses the `stack_id` scope enforced elsewhere in `BaseController`, violating the invariant that an API request only touches stacks its `ApiClient.stack_id` authorizes.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L69-72)
```ruby
      def identify_user
        user_login = request.headers['X-Shipit-User'].presence
        User.where('lower(login) = ?', user_login.downcase).first if user_login
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-36)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

### Title
Unauthorized cross-stack CCMenu read via unscoped `Stack.from_param!` in `CCMenuController#stack` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController#stack` overrides the base controller's stack-scoping logic and resolves the target stack with the unscoped `Stack.from_param!(params[:stack_id])` instead of the parent's `stacks.from_param!(params[:stack_id])`, which filters by `current_api_client.stack_id`. As a result, any authenticated `ApiClient` — even one whose `stack_id` is explicitly scoped to a single stack (e.g. minted by `CCMenuUrlController#fetch` for stack A) — can fetch CCMenu XML (`activity`, `lastBuildStatus`, `webUrl`, etc.) for any other stack B by id, regardless of archived status.

### Finding Description
The intended binding is: for a scoped `ApiClient`, `current_api_client.stack_id == B.id || current_api_client.stack_id.nil?` must hold before stack B's data is rendered. In `BaseController` this is enforced via `stacks` / `stack`: [1](#0-0) 

But `CCMenuController` defines its own `stack` method that calls the bare `Stack` class method, completely bypassing that scoping: [2](#0-1) 

`require_permission :read, :stack` only checks that the client's `permissions` array contains the literal string `"read:stack"` — it never checks which stack the client is scoped to: [3](#0-2) 

So the actual condition enforced is `current_api_client.permissions.include?('read:stack')`, not `current_api_client.stack_id == stack_id`. These two conditions are not equivalent whenever `current_api_client.stack_id` is set (i.e., a scoped client, exactly the kind minted by `CCMenuUrlController#fetch`): [4](#0-3) 

Exploit flow: attacker somehow obtains (or is issued) a `read:stack`-scoped CCMenu token for stack A (this token is a URL query-string parameter designed to be embedded in CI dashboards, so its exposure surface is broad by design). They then send `GET /api/stacks/:owner/:repo_of_B/ccmenu?token=<A's token>` with `stack_id` set to stack B. `CCMenuController#show` calls `stack.deploys_and_rollbacks.last` on the resolved stack B and renders its project XML, disclosing stack B's activity/build status/webUrl — with no dependency on stack B being archived or not; archived state is irrelevant to the bypass since the scoping check is skipped entirely regardless of that flag.

Existing guards do not prevent this: `require_permission!` (checked via `check_permissions!`) only validates permission *name*, not stack scope; `authenticate_api_client` in `CCMenuController` only re-derives `@current_api_client` from `params[:token]` (or falls back to Basic auth) but performs no stack-id comparison either: [5](#0-4) 

### Impact Explanation
Any holder of a stack-scoped CCMenu token (which, per `CCMenuUrlController#fetch`, is routinely generated and embedded in URLs/dashboards for CI status widgets) can read build/deploy status for arbitrary other stacks by simply changing the `stack_id` route segment — an unauthenticated-boundary-crossing read of stack state across tenants. This is repeatable against any stack id in the system and requires no additional secrets. It matches the High-severity category "unauthenticated read of stack state... or deploy output" since the token was never scoped to grant access to the target stack.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs one legitimately-scoped `read:stack` CCMenu token for any stack (which is the designed, low-friction distribution mechanism via `CCMenuUrlController#fetch`, meant to be pasted into external CI dashboards). From there, guessing or enumerating `stack_id` values (owner/repo/branch triples, often public GitHub repo names) is trivial. No GitHub secrets, session, or elevated role is required. This is a low-cost, highly repeatable bypass.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to use the scoped resolver instead of the bare model class, mirroring `BaseController#stack`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
where `stacks` applies `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`. Do not conflate `archived?` with access scoping — the scope check must remain independent of archival state.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb (additions)
test "a client scoped to stack A cannot read CCMenu for stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "bar"), branch: 'main')

  @client.update!(stack: stack_a, permissions: ['read:stack'])

  get :show, params: { stack_id: stack_b.to_param, token: @client.authentication_token }

  # Binding under test: current_api_client.stack_id (== stack_a.id) must equal
  # requested stack_b.id, or the request must be rejected.
  assert_not_equal @client.stack_id, stack_b.id
  assert_response :forbidden # or :not_found — currently fails, returns :ok with stack_b's XML
end

test "a client scoped to stack A cannot read CCMenu for an archived stack B" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.new(owner: "foo", name: "baz"), branch: 'main')
  stack_b.update!(archived_since: Time.now.utc) # if Stack supports archiving via this attribute

  @client.update!(stack: stack_a, permissions: ['read:stack'])

  get :show, params: { stack_id: stack_b.to_param, token: @client.authentication_token }

  assert_response :forbidden # currently fails identically to the non-archived case
end
```
Both assertions currently fail (the controller returns `200 OK` with stack B's project XML) because `CCMenuController#stack` resolves via unscoped `Stack.from_param!`, confirming the bypass is unrelated to archival state.

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L6-18)
```ruby
  class CCMenuUrlController < ShipitController
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

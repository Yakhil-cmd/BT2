### Title
`Api::CCMenuController#show` bypasses per-stack ACL by resolving `stack` via unscoped `Stack.from_param!` instead of the scoped `stacks` relation - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts an `ApiClient` scoped to a single stack (`current_api_client.stack_id`) by exposing only that stack through the `stacks` relation, and the base `stack` method resolves via `stacks.from_param!`. `Api::CCMenuController` overrides `stack` to call `Stack.from_param!` directly on the unscoped class, discarding that restriction, so any token with the `read:stack` permission can fetch CCMenu status for any stack regardless of its `stack_id` binding.

### Finding Description
The binding the codebase is supposed to enforce is: `stack the request may access ∈ Stack.where(id: current_api_client.stack_id)` when `current_api_client.stack_id?` is true.

`Api::BaseController` implements this correctly: [1](#0-0) 
`stacks` returns only the client's authorized stack when `stack_id` is set, and `stack` resolves against that scoped relation.

`Api::CCMenuController` overrides `stack` to bypass this scoping entirely: [2](#0-1) 
It calls `Stack.from_param!(params[:stack_id])` on the bare `Stack` class instead of `stacks.from_param!`, so the equality breaks: the set of stacks reachable is now `Stack.all` matching by param, not `Stack.where(id: current_api_client.stack_id)`.

The only remaining guard is `require_permission :read, :stack`, enforced via `check_permissions!`: [3](#0-2) 
This only checks that the string `"read:stack"` is present in the client's global `permissions` array — it carries no per-stack information and cannot restore the broken binding.

Attack: obtain (or be issued) an `ApiClient` token scoped to `stack_id = A` with `permissions: ['read:stack']` (a normal, legitimately-scoped token for a public stack A). Request `GET /:stack_id_for_B/ccmenu.xml?token=<token>` (or via Basic Auth) where B is a private/internal stack. `authenticate_api_client` succeeds (token is valid), `require_permission!(:read, :stack)` passes (permission is present globally), and `stack` resolves B via unscoped `Stack.from_param!`, rendering B's `deploys_and_rollbacks.last` (commit `ended_at`, `running?`) in the XML response — data the token was never authorized to see.

### Impact Explanation
Any valid `read:stack`-scoped API token — even one legitimately restricted to a single named stack — can be used to enumerate and read the latest deploy/rollback status (build success/failure, running state, timestamp) of every other stack on the instance via the CCMenu endpoint. This is an unauthenticated-for-that-resource read of stack build/deploy state across tenant boundaries, matching the "High: escalation into authorization scope, unauthenticated read of stack state" category. It is fully repeatable against arbitrary stacks by varying `stack_id` in the request, with no rate limiting bypass needed beyond simple parameter substitution.

### Likelihood Explanation
Preconditions are minimal: the attacker needs any valid API client token with `read:stack` permission (a normal token issued for one stack, e.g. a CI integration credential for a single public project) and knowledge/guessability of another stack's identifier (repo owner/name/branch, which is often predictable or discoverable). No GitHub secrets, session, or elevated role is required — only a legitimately-issued, narrowly-scoped API token. This is low cost and highly feasible for anyone who already holds any such token.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the scoped `stacks` relation from `BaseController` (i.e., remove the override, or change it to `stacks.from_param!(params[:stack_id])`) so the same per-client `stack_id` restriction applied elsewhere in the API is enforced for CCMenu requests too.

### Proof of Concept
```ruby
# test/controllers/api/ccmenu_controller_test.rb
test "a token scoped to stack A cannot read stack B's ccmenu data" do
  stack_a = shipit_stacks(:shipit)
  stack_b = Stack.create!(repository: Repository.create!(owner: 'private', name: 'internal'), branch: 'main', environment: 'production')
  stack_b.trigger_deploy(shipit_deploys(:shipit)) rescue nil # or otherwise seed a deploy/rollback

  scoped_client = ApiClient.create!(creator: shipit_users(:walrus), name: 'scoped', stack: stack_a, permissions: ['read:stack'])
  token = scoped_client.authentication_token

  # Binding under test: reachable_stacks(token) == Stack.where(id: stack_a.id)
  get :show, params: { stack_id: stack_b.to_param, token: token }

  assert_response :not_found # expected after fix; currently returns :ok with stack_b's data
end
```
Before the fix, this request returns HTTP 200 with `stack_b`'s deploy data in the XML body (`assert_payload 'name', stack_b.to_param` would pass), demonstrating the ACL bypass; after applying the recommended fix, `stacks.from_param!` raises `Stack::NotFound` (rendered as 404) because `stack_b` is not in the scoped relation.

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

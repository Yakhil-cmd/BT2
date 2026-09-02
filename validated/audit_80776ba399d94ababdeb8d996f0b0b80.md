This confirms the exploit scenario: `here_come_the_walrus` is an `ApiClient` scoped to the `shipit` stack via `stack_id`, with only `read:stack` permission, verified by `test/controllers/api/stacks_controller_test.rb:217-223` showing `authenticate!(:here_come_the_walrus); get :index` only returns 1 stack — confirming that stack scoping is enforced through the `stacks` helper in `StacksController`/`BaseController`. `CCMenuController` bypasses this exact enforcement mechanism.

### Title
API token scoped to one stack can read CI/deploy status of any other stack via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` fetches the target `Stack` directly by `params[:stack_id]` instead of using the `stacks` scoping helper that every other API controller relies on, so an `ApiClient` token scoped to one stack can read deploy/build status for any stack in the installation.

### Finding Description
`Shipit::Api::BaseController` establishes the trust binding between an `ApiClient` token and the stacks it is authorized to touch: `stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` resolves `params[:stack_id]` through that scoped relation: [1](#0-0) 

Every controller that inherits this `stack` method (e.g. `DeploysController`, `StacksController`) is therefore constrained to the stack(s) the token authorizes, as demonstrated by the `here_come_the_walrus` fixture (a client with `stack: shipit` and only `read:stack` permission) which only ever sees its own stack: [2](#0-1) [3](#0-2) 

`CCMenuController`, however, overrides `stack` to bypass the scoping entirely and resolve any stack in the system directly from the unfiltered `Stack` relation: [4](#0-3) 

`require_permission :read, :stack` only checks that the token's permission list contains `read:stack` — it never checks which stack the permission applies to. That check is implemented in `ApiClient#check_permissions!`, which is purely a string-membership test with no `stack_id` comparison: [5](#0-4) 

So the only mechanism that ties a token to a specific stack (`stacks`/`current_api_client.stack_id`) is exactly the mechanism `CCMenuController#stack` skips. This breaks the binding: `stack a token authorizes == stack it touches`.

### Impact Explanation
An `ApiClient` token that was deliberately scoped to a single stack (a common configuration to hand tokens to CI systems, integrations, or other repos' automation with minimal privilege) can be used to read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, `webUrl`) of any other stack in the Shipit installation by simply passing a different `stack_id` in the request. This is an unauthenticated-for-that-resource read of stack/task state across a repository boundary the token was never granted, matching the High-impact category "unauthorized read of stack state ... deploy output."

### Likelihood Explanation
Trivial to exploit: any holder of a stack-scoped API token (already a low-privilege credential intentionally issued for narrow use, e.g. embedding in a CI-status badge as this controller's own name suggests) only needs to change the `stack_id` route parameter or `stack_id`/query value to a different stack's identifier. No additional access, secrets, or race conditions are required.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve the stack through the scoped `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, consistent with `BaseController` and every other API controller, so the `read:stack` permission check is actually enforced against the stack the token is authorized for.

### Proof of Concept
1. Create/observe an `ApiClient` scoped to stack A (`stack_id` set, `permissions: ['read:stack']`) — e.g. the `here_come_the_walrus` fixture scoped to the `shipit` stack.
2. Authenticate as that client and request `GET /shipit/api/stacks/:stack_id_of_a_different_stack/cc.xml` (routed to `CCMenuController#show`) with `token=<here_come_the_walrus token>` and `stack_id` set to some other stack B's slug/id that the client was never granted access to.
3. `authenticate_api_client` succeeds (valid token). `require_permission :read, :stack` passes because the client's permission list contains `read:stack` (no stack comparison). `stack` resolves via `Stack.from_param!(params[:stack_id])` against the full `Stack` table, returning stack B regardless of `current_api_client.stack_id`.
4. The response renders stack B's latest deploy/build status in the CCMenu XML, even though the token was scoped only to stack A — contrast with the equivalent request to `Api::StacksController#show`, which would 404/empty via the scoped `stacks` relation for the same token.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
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

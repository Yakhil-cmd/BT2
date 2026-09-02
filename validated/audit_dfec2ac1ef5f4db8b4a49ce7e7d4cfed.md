### Title
Cross-repository read: `Api::CCMenuController` lets a stack-scoped API token read any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The finding class is "attacker-controlled field is acted upon while bypassing the trust binding it should honor" — analogous to the `fee_receipient` bug where a caller-supplied value substitutes for an implicitly-trusted one. In shipit-engine, `Shipit::Api::BaseController` binds every stack-scoped API request to the `ApiClient`'s authorized stack set via the `stacks` helper, but `Shipit::Api::CCMenuController` overrides `stack` to bypass that binding and resolve `params[:stack_id]` against the global `Stack` relation instead.

### Finding Description
Every other stack-scoped API controller resolves the target stack through `stacks`, which restricts the query to the `ApiClient`'s authorized scope: [1](#0-0) 

That is: `stacks = current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, and `stack = stacks.from_param!(params[:stack_id])`. This is the binding: **the stack a token authorizes == the stack it touches**.

`CCMenuController`, however, defines its own `stack` method that ignores `stacks` entirely and resolves directly against `Stack`: [2](#0-1) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` string permission via `ApiClient#check_permissions!`, which has no notion of *which* stack: [3](#0-2) 

So a token created with `stack_id` set (i.e. intentionally scoped to a single stack, as documented/tested by the `here_come_the_walrus` fixture and the "an api client scoped to a stack will only see that one stack" test) still has `read:stack` in its `permissions` array. When such a token is used against `Api::CCMenuController#show`, `stack` resolves via `Stack.from_param!(params[:stack_id])` — the global relation — not `stacks.from_param!`, so `params[:stack_id]` is trusted to be *any* stack regardless of the token's `stack_id` restriction.

### Impact Explanation
This breaks the equality "stack a token authorizes == stack it touches" and results in an unauthorized cross-stack information read: an attacker holding a token restricted to stack A can pass `stack_id=B` and receive stack B's build status via `Api::CCMenuController#show` (build activity, last build status/label/time, web URL) even without any permission scoped to stack B. Per the impact taxonomy this is "unauthenticated/unauthorized read of stack state" — a High-severity issue since it escalates a narrowly-scoped credential into engine-wide stack-state disclosure.

### Likelihood Explanation
Likelihood is significant because: (1) the attacker only needs a valid, low-privilege stack-scoped `ApiClient` token (these are routinely issued per-project, e.g. auto-created via `CCMenuUrlController` with `permissions: %w[read:stack]` and no stack restriction shown there, but any token minted with a `stack:` restriction and `read:stack` permission is exposed to this bypass); (2) the only additional input needed is guessing/knowing a target `stack_id`, which are typically short, non-secret slugs (e.g. `shopify/shipit-engine/production`); (3) no other validation prevents the mismatch — `require_permission` and `check_permissions!` never consult `current_api_client.stack_id`.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation (as `BaseController#stack` does) instead of the global `Stack` class, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so a stack-restricted `ApiClient` cannot query stacks outside its `stack_id`.

### Proof of Concept
1. Create/mint an `ApiClient` with `stack_id` set to Stack A and `permissions: ['read:stack']` (mirrors the `here_come_the_walrus` fixture pattern used in tests). [4](#0-3) 
2. Authenticate as that client and issue `GET /api/stacks/:stack_id_of_stack_B/ccmenu.xml` using Stack B's `to_param` instead of Stack A's.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` rather than `stacks.from_param!`, the request succeeds and returns Stack B's CCTray XML (`name`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`, etc.), as exercised generically (with an unscoped client) by: [5](#0-4) 
No existing test exercises the scoped-client case against this controller (unlike `Api::StacksControllerTest#"an api client scoped to a stack will only see that one stack"`), and the code path does not enforce the scoping.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-24)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```

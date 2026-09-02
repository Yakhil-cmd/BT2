### Title
CCMenu API endpoint bypasses per-stack `ApiClient` scoping, allowing a stack-scoped token to read any stack's build/deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from `Stack.from_param!(params[:stack_id])`, bypassing the scoping enforced by `Shipit::Api::BaseController#stack`, which restricts lookups to `current_api_client`'s bound stack when the client is stack-scoped. This breaks the binding: "the stack an `ApiClient` token authorizes" vs. "the stack it actually touches."

### Finding Description
`ApiClient` records can optionally be bound to a single `stack` (`belongs_to :stack, optional: true`) [1](#0-0) . The generic API base controller enforces this binding by scoping the `Stack` relation used for lookups:

```
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

This is exactly what `Api::StacksControllerTest` verifies: "an api client scoped to a stack will only see that one stack" [3](#0-2) .

However, `Api::CCMenuController` overrides `stack` and looks the record up unscoped:

```
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

The controller still declares `require_permission :read, :stack` [5](#0-4) , but `ApiClient#check_permissions!` only checks the operation/scope string (`"read:stack"`), not which specific stack row is targeted [6](#0-5) . There is no additional check that `params[:stack_id]` matches `current_api_client.stack_id`.

Root cause: the deployment-trust binding is "token authorises stack X" vs. "controller touches stack Y from user-supplied `params[:stack_id]`," and CCMenuController's custom `stack` method severs that binding while `require_permission` only re-validates the coarse `read:stack` capability, not the specific stack instance.

### Impact Explanation
An attacker holding any valid `ApiClient` token with `read:stack` permission - even one deliberately scoped by an operator to a single, low-sensitivity stack via `stack_id` - can supply an arbitrary `stack_id` in the CCMenu request and read that other stack's build/deploy state (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock status, etc., per `test/controllers/api/ccmenu_controller_test.rb`). This is an unauthenticated-for-that-resource read of stack state across a trust boundary the operator explicitly configured via stack-scoped tokens, matching the "High - unauthenticated read of stack state" impact category. It does not require a GitHub App private key, webhook secret, or session — only an already-issued, narrowly-scoped `ApiClient` token, i.e., no privileged access is being requested beyond what was already granted for a different, single stack.

### Likelihood Explanation
Likelihood is moderate-to-high in any Shipit install that issues stack-scoped `ApiClient` tokens (a documented, intended use case for restricting third-party CI dashboard integrations to a single project) and exposes the CCMenu endpoint (which is specifically designed to be embedded in third-party CI aggregators such as CCMenu/CCTray clients). Exploitation requires only changing the `stack_id`/`token` query parameter on a GET request; no special tooling or timing race is needed (unlike the referenced `selfdestruct` PoC, which required a race between two transactions).

### Recommendation
Make `CCMenuController#stack` route through the same scoped lookup as the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
reusing `BaseController#stacks`, so the `current_api_client.stack_id?` restriction applies uniformly. Add a regression test asserting that a stack-scoped `ApiClient` token receives a not-found/forbidden response when `stack_id` does not match its bound stack (mirroring the existing `Api::StacksControllerTest` scoping test).

### Proof of Concept
1. Operator creates an `ApiClient` bound to `stack_id: A` with `permissions: ["read:stack"]`, intending it to only report on stack `A` (e.g. for embedding in an external CI dashboard).
2. Attacker (holder of that token, e.g. an external integration operator) issues:
   `GET /api/stacks/B/owner/repo/environment/ccmenu.xml?token=<clients_token_for_A>`
   (or via Basic Auth header, with `stack_id` set to `B`'s path).
3. `CCMenuController#authenticate_api_client` authenticates the token successfully via `ApiClient.authenticate(params[:token])` [7](#0-6) .
4. `require_permission :read, :stack` passes because the client's `permissions` array contains `read:stack`, regardless of the specific stack [8](#0-7)  (path corrected: `app/models/shipit/api_client.rb`).
5. `stack` resolves via unscoped `Stack.from_param!(params[:stack_id])`, returning stack `B` even though the token is bound to `A` [4](#0-3) .
6. Response renders stack `B`'s build/deploy status, confirming cross-stack disclosure outside the token's intended scope.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

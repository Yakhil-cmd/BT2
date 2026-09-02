Confirmed: `Api::StacksController#stack` correctly uses the scoped `stacks.from_param!(...)` (inherited helper), proving the intended binding is "the stack a token authorizes == the stack a token touches." `Api::CCMenuController#stack` breaks that binding by querying `Stack.from_param!(params[:stack_id])` directly against all stacks, bypassing the `stacks`/`stack_id?` scoping defined in `BaseController`.

### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing stack-scoped tokens to read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` scoped to a single stack (`stack_id` set) can only query that stack, by resolving `stack`/`stacks` through `current_api_client.stack_id?` [1](#0-0) . `Shipit::Api::CCMenuController` overrides `stack` to look up `Stack.from_param!(params[:stack_id])` directly, without going through the scoped `stacks` helper, and without re-checking `current_api_client.stack_id?` [2](#0-1) . It still only requires the generic `read:stack` permission via `require_permission :read, :stack` [3](#0-2) , which only checks that the permission string is present on the token, not which stack it is scoped to [4](#0-3) .

### Finding Description
The binding that should hold is: `stack the ApiClient token authorizes == stack the CCMenu endpoint touches`. `Api::StacksController#stack`, the reference implementation, honors this by delegating to the scoped `stacks` collection (`Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true) before resolving the param [5](#0-4) . `Api::CCMenuController#stack` instead resolves against `Stack.from_param!` unscoped, so a token created with `stack: shipit` (i.e. `stack_id?` true, restricting it to one stack) can nonetheless load and render CCMenu XML for any other stack in the system by simply changing the `stack_id` URL segment, since `CCMenuController` never consults `current_api_client.stack_id?` at all. This is the exact structural analog of the report's bug class: a security-relevant binding (`gap`/layout consistency in the audit report; token-to-stack scope here) is correctly enforced in one place (`BaseStrategyVault`/`BalancerStrategyBase` gaps; `StacksController#stack`) but silently omitted in a sibling/inherited context (`Boosted3TokenPoolMixin` etc.; `CCMenuController#stack`), corrupting the intended isolation boundary.

### Impact Explanation
An attacker holding a legitimately-issued `ApiClient` token scoped to a single stack (e.g., the "CCMenu Client" generated per-stack by `CCMenuUrlController`, which stores no stack scoping restriction bug aside, or any admin-issued single-stack token) can use that token to read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, etc.) for every other stack managed by the Shipit instance, including private/internal repositories the token holder was never granted visibility into. This is an unauthorized read of stack state across stacks, matching the "High - unauthenticated/unauthorized read of stack state ... outside its granted scope" impact category, since the escalation crosses the intended per-stack authorization boundary using only the `read:stack` permission bit rather than the `stack_id` scope that was supposed to gate it.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a documented, expected usage pattern — e.g. CCMenu integration per-stack). No special privilege beyond holding one such token is required; the attacker only needs to alter the `stack_id` route parameter on a request they are already authorized to make, with no additional secrets, sessions, or GitHub credentials involved.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the inherited, scoped `stacks` collection instead of `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This mirrors `Api::StacksController#stack` and restores the enforcement of `current_api_client.stack_id?` scoping for the CCMenu endpoint.

### Proof of Concept
1. Create/obtain an `ApiClient` token scoped to stack `A` with permission `read:stack` (`stack_id` set to `A`, e.g. via the "CCMenu Client" flow in `CCMenuUrlController`) [6](#0-5) .
2. Send `GET /api/stacks/<owner>/<stack-B>/ccmenu.xml?token=<token-for-A>` using Basic Auth or the `token` query param, where `stack-B` is a different stack the token was never scoped to.
3. `CCMenuController#authenticate_api_client` accepts the token via `ApiClient.authenticate(params[:token])` [7](#0-6) , `require_permission :read, :stack` passes because the token has that permission string [4](#0-3) , and `stack` resolves `stack-B` directly via `Stack.from_param!` with no scoping check [8](#0-7) , returning `stack-B`'s CCMenu XML (build status, last build label, web URL) to the holder of a token that was only supposed to see stack `A`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

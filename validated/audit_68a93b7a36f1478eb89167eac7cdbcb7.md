### Title
API-scoped `ApiClient` token can read any stack's build status via `Api::CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Finding Description
`Shipit::Api::BaseController` implements stack-level authorization scoping for `ApiClient` tokens: when an `ApiClient` is created with a `stack_id`, all stack lookups are supposed to be constrained to that stack via `stacks`/`stack`: [1](#0-0) 

`Api::StacksController` (and the pattern used across the API surface) relies on this scoped helper: [2](#0-1) 

`Api::CCMenuController`, however, overrides `stack` to bypass the scoped lookup entirely, resolving `params[:stack_id]` against the *global* `Stack` relation instead of the client-scoped `stacks` relation: [3](#0-2) 

The controller's only permission gate is `require_permission :read, :stack`, which only checks that the `ApiClient#permissions` array contains the string `"read:stack"` — it never checks that the requested `stack_id` matches `current_api_client.stack_id`: [4](#0-3) 

This is the same class of bug as the reported `cooldownExpiration` issue: a value that *is* checked (the client's stack scope, `current_api_client.stack_id`) is silently dropped from the path that actually resolves the resource (`stack`), so the binding `stack the token authorizes == stack the token touches` is broken. The equality that should hold is:

`current_api_client.stack_id == resolved_stack.id` (when `current_api_client.stack_id?` is true)

but `CCMenuController#stack` never enforces the left-hand side.

### Impact Explanation
Any holder of a valid, stack-scoped `read:stack` `ApiClient` token (e.g. the token minted by `CCMenuUrlController`/"CCMenu Client" flow for one specific stack) can pass an arbitrary `stack_id` to `GET /api/stacks/:stack_id/ccmenu.xml` and read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc.) of any other stack in the Shipit instance, including private or sensitive deployment pipelines the token was never authorized for. This is an authorization-scope escalation / unauthenticated-for-that-resource read of stack state, matching the "escalation into stack authorization" / "unauthenticated read of stack state" High-impact category, since it crosses the deployment-trust boundary that scoped API tokens are meant to enforce.

### Likelihood Explanation
Likelihood is moderate-to-high for any deployment that issues stack-scoped API tokens (the CCMenu integration is a first-party, documented feature) or where an admin creates a scoped `ApiClient` via the `ApiClient` UI restricting it to one stack for least-privilege reasons. Exploitation requires only possession of one valid `read:stack` token — no repository write access, no privileged account, and no additional secrets — and a single unauthenticated-relative-to-target-stack HTTP GET request with a different `stack_id`.

### Recommendation
Make `Api::CCMenuController#stack` consistent with the rest of the API surface by resolving the stack through the scoped relation, e.g.:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

removing the local override so it inherits `BaseController#stack`/`#stacks`, ensuring `current_api_client.stack_id` (when set) is always enforced before rendering any stack data.

### Proof of Concept
1. As an authorized Shipit user, create (or have the app create via `CCMenuUrlController#fetch`) an `ApiClient` scoped to Stack A with permission `read:stack` (matches fixture `here_come_the_walrus`, `stack: shipit`, `permissions: ['read:stack']`) — analogous to fixture: [5](#0-4) 
2. Obtain that client's `authentication_token` (e.g., via the CCMenu URL emailed/linked to the user, or the `api_clients/show` page).
3. Send `GET /api/stacks/<stack_B_id>/ccmenu.xml?token=<token>` where `stack_B` is a *different* stack than the one the client is scoped to.
4. `Api::CCMenuController#authenticate_api_client` authenticates the token successfully, `require_permission :read, :stack` passes because the token has the `read:stack` string, and `#stack` resolves `stack_B` directly via `Stack.from_param!(params[:stack_id])`, returning `stack_B`'s deploy/build status even though the token is scoped to `stack_A`.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

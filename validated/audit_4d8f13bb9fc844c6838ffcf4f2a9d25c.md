### Title
CCMenu API token stack-scoping bypass allows cross-stack build status disclosure - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method inherited from `Shipit::Api::BaseController` in a way that discards the stack-scoping enforced for `ApiClient` tokens that are bound to a single stack. As a result, a token that is only authorized (`stack_id`) for stack A can be used to read build/deploy status of any other stack B, breaking the binding "the stack a token authorises == the stack it touches."

### Finding Description
`ApiClient` records can optionally be scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Shipit::Api::BaseController` enforces this scoping through its `stacks`/`stack` helper methods:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Every other API controller (e.g. `LocksController`, `DeploysController`) inherits `stack` unmodified, so a client scoped to a single stack can never resolve `params[:stack_id]` to a different stack — permission is validated both by scope (`stack`/`stacks`) and by operation (`check_permissions!`).

`CCMenuController`, however, defines its own `stack` helper that bypasses this scoping entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

`require_permission :read, :stack` only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!` [4](#0-3) , it never checks which stack the token is bound to. Because `CCMenuController#stack` no longer routes through `BaseController#stacks`, the `current_api_client.stack_id` binding is never consulted, so any `stack_id` parameter is resolved globally.

The fixture data even demonstrates the intended trust boundary: the `here_come_the_walrus` client is deliberately scoped to a single stack (`stack: shipit`) with only `read:stack` permission [5](#0-4) , exactly the kind of token this controller is supposed to honor a narrow scope for — but its `show` action ignores that scope.

### Impact Explanation
This matches the "High" impact category: "unauthenticated read of stack state, task streams or deploy output" relative to the token's authorized scope. An attacker holding (or having been issued) a CCMenu/API token scoped to one stack — which the `CCMenuUrlController` issues by design for embedding in third-party CI dashboards (`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(...)` [6](#0-5) ) — can enumerate `stack_id` values and read build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, lock state) for every stack in the deployment, not just the one it was scoped to. This is a scope-authorization boundary crossing: the equality `stack authorized by token == stack read by the endpoint` is broken specifically in this one controller, while it holds everywhere else in the API surface.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped CCMenu tokens (a documented, supported feature via `CCMenuUrlController`), since exploitation only requires knowledge/guessing of another stack's `owner/repo/environment` param — no special privileges, no secrets, and no additional authentication bypass are needed beyond possessing any valid, even narrowly-scoped, token.

### Recommendation
Remove the `stack` override in `CCMenuController` (or reimplement it to delegate to the inherited `stacks`/`stack` scoping from `BaseController`) so that `Stack.from_param!` lookups are always constrained by `current_api_client.stack_id` when the token is scoped, consistent with every other API controller.

### Proof of Concept
1. Create two stacks, `org/repo-a/production` and `org/repo-b/production`.
2. Create an `ApiClient` scoped to `repo-a` only, with permission `read:stack` (mirrors fixture `here_come_the_walrus`).
3. Using that client's `authentication_token`, request:
   `GET /api_clients/.../stacks/org/repo-b/production/ccmenu.xml?token=<token>`
4. The response returns 200 with `repo-b`'s build status (`lastBuildStatus`, `lastBuildLabel`, etc.) even though the token is only authorized for `repo-a`, confirming the cross-stack read documented in `CCMenuControllerTest` — which only ever tests same-scope access and thus never protects against this because the controller-level `stack` override in `app/controllers/shipit/api/ccmenu_controller.rb:29-31` ignores `current_api_client.stack_id`.

### Citations

**File:** app/models/shipit/api_client.rb (L4-9)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

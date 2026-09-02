### Title
CCMenu endpoint bypasses ApiClient stack-scope binding, letting a stack-scoped token read any stack's state - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`PaladinRewardReserve`'s bug class is that a permission record (`approvedSpenders`) is not tied to the specific `token` it was granted for, so a check performed for one context is silently reused for another. The same class of bug exists in Shipit's API authorization layer: an `ApiClient` can be scoped to a single `Stack` (`ApiClient#stack_id`), and every API controller resolves the target stack through `BaseController#stack`, which enforces that scope. `CCMenuController` re-implements `#stack` on its own, dropping the scope check, so the binding "stack a token authorises" == "stack it touches" is broken for this one endpoint.

### Finding Description
`Shipit::ApiClient` can be optionally bound to one `Stack` via `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces this binding by scoping stack lookups: `stacks` returns only the client's own stack when `stack_id` is set, and `stack` resolves the requested `params[:stack_id]` against that scoped relation: [2](#0-1) 

`ApiClient#check_permissions!` only checks that the permission string (e.g. `read:stack`) is present in the client's `permissions` array; it has no knowledge of *which* stack is being acted on: [3](#0-2) 

so the stack-match check exists solely in `BaseController#stack`/`#stacks`. Every other API controller (`TasksController`, `DeploysController`, `RollbacksController`, `MergeRequestsController`, `OutputsController`, `ReleaseStatusesController`, `CommitsController`) relies on that inherited, scoped `#stack` method [4](#0-3) [5](#0-4) .

`Api::CCMenuController`, however, overrides `#stack` to bypass the scoped relation entirely and resolve the parameter against `Stack.from_param!` directly: [6](#0-5) 

Because `require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)` [7](#0-6) , and that check never inspects `stack_id`, any `ApiClient` holding `read:stack` — even one that the UI created and scoped to a single stack, like the `here_come_the_walrus` fixture (`stack: shipit`, `permissions: [read:stack]`) [8](#0-7)  — can call `GET /api/stacks/*stack_id/ccmenu` for **any other stack** and receive its build/deploy status, lock state, and web URL.

Before the attacker's action: token T is bound to `stack_id = A` and is only supposed to authorize reads of stack A (`stacks` scope == `{A}` for every other endpoint). After hitting `Api::CCMenuController#show` with `stack_id = B`: T successfully reads stack B's state, because `#stack` resolves `B` unconditionally via `Stack.from_param!`, never intersecting with T's `stack_id`. The equality that should hold — `stack the token authorises == stack the token touches` — is broken specifically on this endpoint.

### Impact Explanation
This is a cross-stack information-disclosure / authorization-scope escalation: a token deliberately restricted (by an administrator) to one stack can be used to read the state — deploy status, lock status, last-build time/label, `webUrl` — of every other stack in the Shipit instance. This matches the "High — escalation into ... unauthenticated read of stack state" impact category, since it defeats the per-stack scoping mechanism that `ApiClient.stack` is meant to enforce.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment that issues stack-scoped `read:stack` tokens (this is the exact intended use case demonstrated by `CCMenuUrlController`, which mints a `read:stack`-only client) [9](#0-8) . Any holder of such a token — e.g., a CI dashboard operator who was only meant to see one stack's build status — can trivially enumerate other stacks and pull their status with the same credential, since the CCMenu route accepts an arbitrary `stack_id` and the token check is scope-blind. No additional privilege is required beyond possessing one legitimately-issued stack-scoped `read:stack` token.

### Recommendation
Remove `CCMenuController`'s private `#stack` override and let it fall back to the inherited, scoped `BaseController#stack`/`#stacks` implementation, so the stack lookup is intersected with `current_api_client.stack_id` exactly like every other API controller. If unscoped CCMenu access is intentional for tokens with no `stack_id`, that already works via the inherited method (`stacks` returns `Stack.all` when `stack_id` is blank); the override provides no needed extra behavior and only removes the scope enforcement.

### Proof of Concept
1. Admin creates (or the system auto-creates via `CCMenuUrlController#client`) an `ApiClient` scoped to Stack A with `permissions: ['read:stack']`, and hands its authentication token to a CI tool for Stack A only.
2. Attacker (or the CI tool, or anyone who obtains the token) issues:
   `GET /api/stacks/<owner>/<repo>/<envB>/ccmenu?token=<tokenScopedToA>`
   where `envB` identifies a different stack B that the token was never granted access to.
3. `CCMenuController#authenticate_api_client` authenticates the token successfully (it is a valid, just differently-scoped, `ApiClient`) [10](#0-9) .
4. `require_permission :read, :stack` passes because the token's `permissions` array contains `read:stack`, regardless of stack B [3](#0-2) .
5. `#stack` resolves stack B via unscoped `Stack.from_param!` [11](#0-10) , and the response renders stack B's live deploy/lock/build status — data the token holder was never authorized to see.

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

**File:** app/controllers/shipit/api/base_controller.rb (L18-21)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
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

**File:** app/controllers/shipit/api/tasks_controller.rb (L9-11)
```ruby
      def index
        render_resources(stack.tasks)
      end
```

**File:** app/controllers/shipit/api/deploys_controller.rb (L8-10)
```ruby
      def index
        render_resources(stack.deploys_and_rollbacks)
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

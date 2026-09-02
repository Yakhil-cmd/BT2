### Title
Stack-scoped `ApiClient` tokens can read any stack's build status via `CCMenuController`, bypassing the token's authorized stack binding - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces the binding "the stack(s) an `ApiClient` token authorizes == the stack it can touch" by scoping the `stack`/`stacks` helpers to `current_api_client.stack_id` when the token is stack-scoped. [1](#0-0) 
`CCMenuController`, however, overrides `stack` to bypass that scoping entirely, resolving the stack directly from the request parameter regardless of which stack the authenticated `ApiClient` is bound to. [2](#0-1) 

### Finding Description
`ApiClient` records can optionally be scoped to a single stack (`belongs_to :stack, optional: true`), and this scoping is the mechanism by which a narrowly-issued, "semi-trusted" CI/CCTray token is prevented from reading data about stacks it wasn't issued for. [3](#0-2) 
The fixture `here_come_the_walrus` demonstrates this pattern in practice: it is created with `stack: shipit` and only the `read:stack` permission, i.e., it is meant to read status for the `shipit` stack only. [4](#0-3) 

`ApiClient#check_permissions!` only checks the coarse `operation:scope` string (e.g. `read:stack`) - it has no knowledge of which specific stack is being requested. [5](#0-4) 
The actual per-stack restriction is enforced only by `BaseController#stacks`/`#stack`, which intersects the requested stack with `Stack.where(id: current_api_client.stack_id)`. [1](#0-0) 

`CCMenuController` redefines `stack` to call `Stack.from_param!(params[:stack_id])` directly, skipping the `stacks` scoping helper entirely, and also implements its own `authenticate_api_client` that accepts the token as a query-string parameter (`params[:token]`) for CCTray-compatible clients. [6](#0-5) 

Because `require_permission :read, :stack` only validates the string permission and not the stack binding, and `stack` no longer filters by `current_api_client.stack_id`, any authenticated client holding `read:stack` - even one explicitly scoped to a single stack such as `shipit` - can pass an arbitrary `stack_id` and retrieve build/deploy status for a stack it was never authorized to access.

Binding broken: `current_api_client.stack_id (the stack the token authorizes)` ≠ `params[:stack_id] resolved via Stack.from_param! (the stack actually touched)`.

Before the flaw: for every other API controller (`DeploysController`, `StacksController`, `TasksController`, etc.), `stack` is resolved through `stacks.from_param!`, so `stack.id == current_api_client.stack_id` whenever the token is scoped. [1](#0-0) 
After the flaw: in `CCMenuController`, `stack.id` can be any stack the requester names, independent of `current_api_client.stack_id`. [7](#0-6) 

### Impact Explanation
This allows unauthorized read of another stack's deploy/task status (latest deploy id, running/success/failure state, timestamps) through the CCTray XML endpoint, which is information about deployments (task/deploy state) that is only supposed to be reachable by clients holding a token scoped to that specific stack. This matches the in-scope "High - unauthenticated/unauthorized read of stack state, task streams or deploy output" impact category, since it lets a token that was deliberately scoped down (a lower-trust CI badge/token, as in the `here_come_the_walrus` fixture) read status data across stacks outside its authorized boundary.

### Likelihood Explanation
Likelihood is high for any deployment using per-stack scoped `ApiClient` tokens (a documented, supported feature) combined with CCTray/CCMenu integration: the attacker only needs a single valid, narrowly-scoped `read:stack` token (e.g., one meant to expose only a public build badge for one stack) and can simply substitute a different `stack_id` in the request to enumerate other stacks' status, requiring no privileged account, no GitHub credentials, and no additional exploitation steps.

### Recommendation
Make `CCMenuController#stack` go through the same scoped resolution as the rest of the API (`stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `current_api_client.stack_id` binding is enforced consistently across all API controllers.

### Proof of Concept
1. Create/observe an `ApiClient` scoped to stack `shipit` with only `read:stack` permission (as in `test/fixtures/shipit/api_clients.yml`, `here_come_the_walrus`). [4](#0-3) 
2. Authenticate as that client (`Authorization` header or `?token=` query param, both supported by `CCMenuController#authenticate_api_client`). [8](#0-7) 
3. Request `GET /api/<other_owner>/<other_repo>/<other_environment>/cc_menu` (the `stack_id` param resolved via `Stack.from_param!`) for a stack this client was never scoped to. [7](#0-6) 
4. The controller renders the CCTray XML for the unrelated stack (`stack.deploys_and_rollbacks.last`), leaking its build/deploy status despite the token being authorized for only `shipit`, because `check_permissions!` only validates the string `read:stack` and never compares `current_api_client.stack_id` to the resolved stack. [5](#0-4)

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

**File:** app/models/shipit/api_client.rb (L1-9)
```ruby
# frozen_string_literal: true

module Shipit
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

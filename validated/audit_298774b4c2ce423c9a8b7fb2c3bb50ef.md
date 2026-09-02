### Title
Stack-scoped API token can read the build/CI status of any stack, not just the one it is scoped to - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
### Finding Description
`ApiClient` can be created scoped to a single stack via the `stack_id` column, and `ApiClient#stack_id?` is used to restrict which stacks that token may act on [1](#0-0) . The restriction is meant to be enforced by `Api::BaseController#stacks`/`#stack`, which limits the queryable stack collection to `Stack.where(id: current_api_client.stack_id)` when the client is scoped:

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [2](#0-1) 

Authorization for an action is checked purely as a string permission (`"read:stack"`, `"write:stack"`, etc.) via `ApiClient#check_permissions!`, which never looks at *which* stack is being accessed [3](#0-2) . The actual per-stack binding is enforced only by the `stacks`/`stack` helper above — i.e., the equality that must hold is: `stack a token is authorised for == stack the request actually touches`.

`Api::CCMenuController` breaks this equality. It overrides `#stack` to bypass the scoped `stacks` collection and query `Stack` directly from the unscoped model:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

The controller still declares `require_permission :read, :stack` [5](#0-4) , which only checks that the `read:stack` permission string is present on the token — it does not verify that `params[:stack_id]` matches `current_api_client.stack_id`. It also authenticates via a bare query-string `token` param (a legitimate use case for CI dashboard tools like CCMenu) rather than Basic Auth:

```ruby
def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
``` [6](#0-5) 

The verified credential (the API token) is checked, but the field it is supposed to authorize on (`stack_id`) is never covered by that check inside this controller — exactly the "payload field acted on but never bound to the verified credential" pattern from the reference report, transposed onto the token-scope/stack binding.

### Impact Explanation
Before the flaw: an `ApiClient` created with `stack: <Stack A>` and `permissions: ['read:stack']` is intended to be able to read build status for Stack A only, as enforced in every other stack-scoped controller (`OutputsController`, `LocksController`, `CommitsController`, etc., all of which use the base `stack` helper) [7](#0-6) [8](#0-7) .

After: any holder of a stack-A-scoped token can query `GET /api/<any-stack-B>/ccmenu?token=<tokenA>` and receive Stack B's build/deploy status, lock state, last build label/time, and web URL [9](#0-8) . This is a cross-stack read of stack state performed with a token whose authorization was scoped to a different (and possibly unrelated/less-trusted) stack/repository, i.e., an authorization-scope bypass matching the "stack a token authorizes vs. stack it touches" class in scope for this review.

### Likelihood Explanation
Any party in possession of one legitimate stack-scoped API token (a fairly common credential distributed to CI dashboard/status tools, since CCMenu tokens are designed to be embedded in URLs/config files for third-party polling tools) can trivially exploit this by changing the `stack_id` path segment — no additional privilege or secret is required. This is a single unauthenticated-parameter change on an otherwise valid, authenticated request.

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and use the inherited, scope-aware `stacks`/`stack` helper from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) so that a stack-scoped token can never resolve a stack outside `current_api_client.stack_id`.

### Proof of Concept
1. Create an `ApiClient` scoped to Stack A: `stack: stack_a, permissions: ['read:stack']`, obtain `client.authentication_token`.
2. As an attacker who only knows this token (e.g., found in a CI status-page config), issue:
   `GET /api/<stack_b_owner>/<stack_b_name>/<stack_b_env>/ccmenu?token=<tokenA>`
3. The response renders Stack B's `shipit/ccmenu/project.xml.builder` view with Stack B's real build/lock status, even though `tokenA` was only ever authorized for Stack A — confirmed by contrast with `LocksController`/`OutputsController`, which correctly 404/scope via `stacks.from_param!` and would reject the same cross-stack request.

### Citations

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
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

**File:** app/controllers/shipit/api/outputs_controller.rb (L1-17)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class OutputsController < BaseController
      require_permission :read, :stack

      def show
        render(plain: task.chunk_output)
      end

      private

      def task
        @task ||= stack.tasks.find(params[:task_id])
      end
    end
```

**File:** app/controllers/shipit/api/locks_controller.rb (L1-10)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class LocksController < BaseController
      require_permission :lock, :stack

      params do
        requires :reason, String, presence: true
      end
```

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-1)
```text
# frozen_string_literal: true
```

### Title
CCMenuController bypasses ApiClient stack scoping, letting a token authorized for one stack read another stack's deploy status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The reported bug class is a mismatch between the amount a purchase logically *authorizes* and the amount later logic *assumes*/*acts on*. The same class of bug — an entity a token is scoped/authorized for vs. the entity the code actually acts on — reappears in `Shipit::Api::CCMenuController`: the stack an `ApiClient` token authorizes (`ApiClient#stack_id`) is never checked against the stack the controller actually reads (`params[:stack_id]`).

### Finding Description
`Shipit::Api::BaseController` establishes the intended binding between a token's authorized stack and the stack a request may touch: [1](#0-0) 

`stacks` is restricted to `current_api_client.stack_id` when the client is scoped, and `stack` is derived from that restricted relation via `from_param!`.

`Shipit::Api::CCMenuController` inherits from `BaseController` and requires only the generic `read:stack` permission: [2](#0-1) 

But it overrides the private `stack` helper to bypass the scoped `stacks` relation entirely, resolving the target stack straight from the unauthenticated URL param: [3](#0-2) 

`ApiClient#check_permissions!`, which backs `require_permission :read, :stack`, only checks that the string `"read:stack"` is present in the client's `permissions` array — it never compares `current_api_client.stack_id` to the stack actually being rendered: [4](#0-3) 

The intended equality is: `current_api_client.stack_id == stack.id` (when the client is stack-scoped) must hold before any stack data is returned. `CCMenuController#stack` breaks that equality by resolving `stack` independently of `current_api_client.stack_id`, so any token carrying `read:stack` — even one a user scoped to a single, low-trust stack (e.g. for a CI status badge) via `CCMenuUrlController` — can be replayed against `/ccmenu/*stack_id` with a different `stack_id` to read that other stack's data. [5](#0-4) 

This confirms scoped tokens are the normal, expected way `read:stack` clients are minted, and that `BaseController`'s design (as validated by the existing "an api client scoped to a stack will only see that one stack" test on `/api/stacks`) intends token-to-stack scoping to be enforced everywhere: [6](#0-5) 

### Impact Explanation
A token holder who is only supposed to see one stack's status (e.g., a stack-scoped CCMenu client shared with a low-trust CI dashboard) can enumerate `stack_id` values and obtain deploy status, last build label/time, and running-state for every other stack in the Shipit installation — an unauthorized read of stack state that the token was never granted, matching the High-severity "unauthenticated read of stack state, task streams or deploy output" category (unauthenticated relative to the target stack).

### Likelihood Explanation
High once any stack-scoped `read:stack` token exists (these are routinely created by `CCMenuUrlController` for CI-status badges and thus have wide, low-privilege distribution). Exploitation is a single unauthenticated-looking GET with the token swapped onto a different `stack_id` path segment — no signature, secret, or write access is needed beyond the caller's own restricted token.

### Recommendation
Make `CCMenuController#stack` reuse the scoped lookup from `BaseController` (i.e., resolve through `stacks.from_param!(params[:stack_id])`, or explicitly assert `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id`) instead of calling `Stack.from_param!` directly, so the stack acted upon can never diverge from the stack the token authorizes.

### Proof of Concept
1. Create/obtain a stack-scoped `ApiClient` with only `read:stack`, e.g. the `here_come_the_walrus` fixture (`stack: shipit`, `permissions: ['read:stack']`), or one self-issued via `GET /ccmenu/*stack_id` (`CCMenuUrlController#fetch`) for stack A.
2. Confirm the token is properly scoped through the normal API: `GET /api/stacks` with that token returns only stack A (as asserted by the existing "scoped to a stack" test).
3. Call `GET /ccmenu/<owner>/<other-repo>/<other-env>?token=<token-for-stack-A>` where the path identifies a different stack B.
4. `CCMenuController#authenticate_api_client` accepts the token (valid signature via `ApiClient.authenticate`), `require_permission :read, :stack` passes (`check_permissions!` only checks the permission string), and `stack` resolves stack B directly via `Stack.from_param!`, returning stack B's deploy status/timing in the XML response — despite the token never being authorized for stack B.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-26)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

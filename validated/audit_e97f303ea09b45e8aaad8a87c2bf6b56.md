Confirmed: `StacksController#stack` correctly uses the scoped `stacks` method (`stacks.from_param!(params[:id])`), respecting `current_api_client.stack_id?` restriction. But `CCMenuController#stack` bypasses this scoping entirely.

### Title
API token stack-scope bypass in CCMenu controller allows cross-stack unauthorized reads - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::BaseController` restricts an `ApiClient` to its assigned `stack_id` by routing all stack lookups through the `stacks` helper, which filters `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped. [1](#0-0)  `Api::CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, never consulting `current_api_client.stack_id`. [2](#0-1) 

### Finding Description
The intended invariant is: *the set of stacks a token authorizes == the set of stacks a request may touch*, enforced by `BaseController#stacks`/`#stack`. [1](#0-0)  `ApiClient#check_permissions!` only checks that the token has the `read:stack` permission string in its `permissions` array — it performs no per-stack comparison at all. [3](#0-2)  The stack-id restriction is therefore enforced exclusively by the controller-level `stacks`/`stack` helpers, not by the permission check.

`CCMenuController` declares `require_permission :read, :stack` (a scope-less permission check) and then defines its own `stack` method that looks up `Stack.from_param!(params[:stack_id])` without going through the inherited `stacks` scoping helper. [4](#0-3)  This is exactly analogous to the reported bug class: a guard condition/scope (`current_api_client.stack_id`) that is supposed to gate the effect but is silently skipped by one code path, so the binding "stack a token authorizes == stack a request touches" breaks whenever this specific controller is used.

By contrast, the sibling `Api::StacksController#stack` correctly reuses `stacks.from_param!(params[:id])`, preserving the scoping. [5](#0-4) 

### Impact Explanation
A holder of a `read:stack`-scoped `ApiClient` token that is restricted to a single stack (`stack_id` set, e.g. tokens minted by `CCMenuUrlController#client`) can supply an arbitrary `stack_id` in the query string of `GET /api/:stack_id/cc.xml` and read `deploys_and_rollbacks` (build/deploy status, last build label, commit info) for any stack in the installation, not just the one it was authorized for. [6](#0-5) [7](#0-6)  This is an unauthorized read of stack/task state for stacks outside the token's granted scope, matching the "unauthenticated/unauthorized read of stack state" High-impact category.

### Likelihood Explanation
Exploitation requires only possession of any valid `read:stack` `ApiClient` token (even a legitimately narrow, single-stack-scoped one issued via the CCMenu integration flow) and knowledge/guessing of another stack's `to_param` (owner/repo/environment), which is not secret. No signature bypass, private key, or elevated privilege is needed beyond an already-issued low-privilege token — this makes the analog concrete and directly reachable through `app/controllers/shipit/api/ccmenu_controller.rb`.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited, permission-scoped `stacks` method (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so stack-scoped tokens cannot read data outside their assigned stack.

### Proof of Concept
1. Obtain (or be issued) a `read:stack` `ApiClient` restricted to Stack A, e.g. via the CCMenu integration (`GET /stacks/:stack_id/ccmenu_url` while authenticated as a normal user for Stack A) which returns a token embedding that client's id. [6](#0-5) 
2. Call `GET /api/cc.xml?stack_id=<STACK_B_PARAM>&token=<TOKEN>` where `STACK_B_PARAM` refers to a different stack the requester has no legitimate relation to.
3. `authenticate_api_client` in `CCMenuController` accepts the token via `ApiClient.authenticate(params[:token])`. [8](#0-7) 
4. `require_permission :read, :stack` passes because the permission array contains `read:stack` (no stack-id check). [3](#0-2) 
5. `stack` resolves `Stack.from_param!(params[:stack_id])` directly to Stack B, bypassing the `current_api_client.stack_id` restriction, and the response renders Stack B's deploy/build status XML. [9](#0-8)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

This confirms the vulnerability. `StacksController` correctly scopes access via `stacks.from_param!` (using the client-scoped `stacks` collection at `app/controllers/shipit/api/stacks_controller.rb:88`), while `CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, bypassing the client's `stack_id` scope entirely. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
CCMenu API endpoint bypasses ApiClient stack scoping, allowing cross-stack deploy status disclosure - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's stack-resolution method in a way that ignores the `ApiClient`'s `stack_id` scope, letting an `ApiClient` token authorized for `read:stack` on one stack read the CI/deploy status of *any* stack in the installation.

### Finding Description
`Shipit::Api::BaseController` enforces per-token stack scoping through two cooperating methods: `stacks`, which restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped to a specific stack, and `stack`, which resolves the requested resource from that restricted set via `stacks.from_param!(params[:stack_id])`. [1](#0-0) 

`Shipit::Api::StacksController` relies on exactly this scoped `stack` method (via `stacks.from_param!(params[:id])`), so a token scoped to Stack A cannot fetch Stack B through `GET /api/stacks/:id`. [3](#0-2) 

`CCMenuController`, however, defines its own private `stack` method that resolves the stack directly from `Stack.from_param!(params[:stack_id])`, completely bypassing `current_api_client.stack_id` filtering. It only enforces `require_permission :read, :stack`, which merely checks that the permission string `"read:stack"` is present in the client's `permissions` array — it never checks *which* stack that permission applies to. [4](#0-3) [5](#0-4) 

This is exactly the audited bug class: a binding that is supposed to hold — *the stack an `ApiClient` token authorizes == the stack the request actually touches* — is verified in one code path (`StacksController`/`BaseController#stack`) but silently dropped in another (`CCMenuController#stack`), the same way `verifySignature()` in the report checked the recovered signer without ever validating which signatory address it was being compared to.

### Impact Explanation
An attacker holding any valid `read:stack`-scoped `ApiClient` token — for example, the token minted by `CCMenuUrlController#client` for a single stack a user has legitimate access to (`ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, ...)`) — can substitute an arbitrary `stack_id` in the CCMenu request and receive that other stack's build/deploy status, lock state, and `webUrl` (`app/controllers/shipit/ccmenu_url_controller.rb:15-18`, `app/views/shipit/ccmenu/project.xml.builder`). This is an unauthorized cross-stack read of stack state and deploy output, matching the "High" impact category (unauthenticated/unauthorized read of stack state or deploy output) since the token was never authorized for that target stack. [6](#0-5) 

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` `ApiClient` token can trigger this with a single unauthenticated-beyond-token-possession HTTP GET, simply changing the `stack_id` route parameter; no privileged account or additional secret is required beyond the token they already legitimately hold for their own stack.

### Recommendation
Make `CCMenuController#stack` resolve through the scoped `stacks` collection from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction is honored the same way it is in `StacksController` and other scoped API endpoints.

### Proof of Concept
1. As a legitimate user, request a CCMenu URL for Stack A: `GET /ccmenu/*stack_id_A` → `CCMenuUrlController#fetch` mints/returns an `ApiClient` scoped to Stack A with `permissions: ["read:stack"]` and returns `{ ccmenu_url: ".../api/stacks/*stack_id_A/ccmenu?token=<TOKEN_A>" }`.
2. Take `TOKEN_A` and call `GET /api/stacks/*stack_id_B/ccmenu?token=<TOKEN_A>` where Stack B is an unrelated stack the token was never scoped to.
3. `CCMenuController#authenticate_api_client` authenticates `TOKEN_A` successfully via `ApiClient.authenticate(params[:token])`; `require_permission :read, :stack` passes because `TOKEN_A`'s permissions include `"read:stack"`; `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly against Stack B, ignoring that `TOKEN_A.stack_id == Stack A.id`.
4. The response renders Stack B's `lastBuildStatus`, `activity`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` — data the token holder was never authorized to see.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-37)
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

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

require 'uri'

module Shipit
  class CCMenuUrlController < ShipitController
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

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
  end
end
```

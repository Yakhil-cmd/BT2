### Title
Stack-scoped ApiClient can read any stack's CI status via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::StacksController` (and the rest of the stack-scoped API surface) resolve the target `Stack` through the `stacks` helper, which restricts lookups to `current_api_client.stack_id` when the client is scoped to a single stack: `@stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` and `@stack ||= stacks.from_param!(params[:id])`. [1](#0-0) [2](#0-1)  `Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: `@stack ||= Stack.from_param!(params[:stack_id])`, looking the stack up directly on the unscoped `Stack` model rather than through `stacks`. [3](#0-2) 

### Finding Description
This breaks the binding: *the set of stacks a token authorizes* (`current_api_client.stack_id`) *must equal the set of stacks a token can touch*. `ApiClient` can optionally be scoped to a single stack via `belongs_to :stack, optional: true`. [4](#0-3)  Every other stack-scoped controller (e.g. `StacksController#stack`) honors that scope by routing lookups through `BaseController#stacks`, which filters to `Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true. [1](#0-0) 

`CCMenuController` requires only the coarse-grained `read:stack` permission (`require_permission :read, :stack`), which `ApiClient#check_permissions!` checks purely against the client's `permissions` list, with no awareness of which specific stack is being accessed: `unless permissions.include?(required_permission) ... raise InsufficientPermission`. [5](#0-4) [6](#0-5)  Because `CCMenuController#stack` resolves via `Stack.from_param!` instead of `stacks.from_param!`, an `ApiClient` that is scoped to stack A and merely holds the `read:stack` permission can supply any other stack's `stack_id` (an id/`to_param`, both public/enumerable identifiers used throughout the routes) and successfully hit `GET /api/stacks/:stack_id/ccmenu`, returning that other stack's deploy/build status (`stack.deploys_and_rollbacks.last`, lock state, last build label, etc.) without ever holding a token scoped to that stack. [7](#0-6) 

`CCMenuUrlController`, the mechanism that mints these scoped `ApiClient`s, explicitly creates a client with `permissions: %w[read:stack]` (no `stack:` association is set on it explicitly, but the general per-stack scoping model, as exercised throughout the app, e.g. `stacks_controller_test.rb`'s test "an api client scoped to a stack will only see that one stack", assumes stack_id-scoped clients are confined to their stack): `@client ||= ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`. [8](#0-7)  Whether or not this particular factory sets `stack_id`, the `CCMenuController#stack` override applies to *any* `ApiClient` with `read:stack`, including deliberately stack-scoped clients created elsewhere in the deployment (e.g. via the `ApiClientsController` UI, which lets users create clients scoped to a specific stack). Any such stack-scoped, read-only credential is silently upgraded to a global read-any-stack credential purely because of this one controller's bypass of the shared `stacks` accessor.

### Impact Explanation
This is an unauthenticated (relative to the target stack) read of stack state/build/deploy status — a credential explicitly minted to authorize reads for one stack can read the CI/deploy status of every stack in the installation, including stacks belonging to unrelated repositories/teams the token holder should have no visibility into. This matches the "High" impact tier: "unauthenticated read of stack state, task streams, or deploy output" via escalation past the token's authorized scope.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient`s with `read:stack` permission (the documented/intended mechanism for restricting a client's visibility to a single stack, as tested in `stacks_controller_test.rb`'s "an api client scoped to a stack will only see that one stack" and enforced in every other stack-scoped API controller). The `CCMenuController` is reachable with just Basic-Auth-style token credentials (`authenticate!` sets `Authorization: Basic <token>`, or the token can be passed as a `token` query param) and requires no special session, GitHub identity, or elevated permission set beyond the read:stack scope already held by the caller. [9](#0-8)  No additional secret or privileged access is needed — only an existing, legitimately-scoped `read:stack` token for any single stack.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the shared, scope-aware `stacks` helper instead of the unscoped `Stack` model, i.e. `@stack ||= stacks.from_param!(params[:stack_id])`, consistent with `StacksController#stack`. Add a regression test asserting that an `ApiClient` scoped to stack A receives a `404`/`403` when requesting `GET /api/stacks/:stack_id/ccmenu` for stack B.

### Proof of Concept
1. As an authorized Shipit user, create (or have the app create via `CCMenuUrlController#fetch`) an `ApiClient` scoped to Stack A with `permissions: ['read:stack']`, and note its `authentication_token`.
2. Using that token, issue: `GET /api/stacks/:stack_B_param/ccmenu` with `Authorization: Basic <base64(token)>` (or `?token=<token>`), where `stack_B` is any other stack in the same Shipit installation that the token was never scoped to.
3. Observe that `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (bypassing the `stack_id?`-based `stacks` scoping used everywhere else) and returns a `200 OK` with Stack B's CI/deploy XML status, despite the token only being authorized for Stack A.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

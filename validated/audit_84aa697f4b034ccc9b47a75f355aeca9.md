### Title
API `ApiClient` stack-scoping bypass in `Api::CCMenuController` - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::BaseController` enforces that a stack-scoped `ApiClient` token can only access the specific `Stack` it was created for, by resolving stacks through a scoped `stacks`/`stack` helper. `Api::CCMenuController` overrides the `stack` accessor and resolves it directly from the global `Stack` table instead of going through that scoping helper, breaking the binding between "the stack a token authorizes" and "the stack the request actually touches."

### Finding Description
`Api::BaseController#stacks` and `#stack` scope stack lookups to the authenticated `ApiClient`'s authorized stack when the client is stack-scoped: [1](#0-0) 

This is the mechanism that turns `read:stack`/`write:stack`/etc. permissions into a per-stack authorization boundary: a client created with `stack_id` set is meant to only ever resolve `stack` to that one `Stack` row, no matter what `stack_id` is supplied in the request.

`Api::CCMenuController`, however, defines its own `stack` method that talks to `Stack` directly, bypassing the scoping entirely: [2](#0-1) 

The controller still declares `require_permission :read, :stack`, but `require_permission!` only checks that the permission string `"read:stack"` is present in `current_api_client.permissions` — it never checks `current_api_client.stack_id` against the requested `stack_id`: [3](#0-2) [4](#0-3) 

So the only place stack-scoping is normally enforced (`stacks`/`stack` in `BaseController`) is exactly the place `CCMenuController` deliberately reimplements without scoping: [5](#0-4) 

The equality that should hold is: `stack authorized by ApiClient == stack acted on by request`. Before the request, for a stack-scoped client, `current_api_client.stack_id == requested Stack.id` is enforced by every other `Api::*Controller` through `stacks`/`stack`. After hitting `Api::CCMenuController#show`, that equality is not checked — any `stack_id` in the URL is resolved via `Stack.from_param!` regardless of `current_api_client.stack_id`.

### Impact Explanation
Any valid `ApiClient` token with the `read:stack` permission — even one deliberately scoped by its creator to a single specific stack — can be used to read the CCMenu XML status (latest deploy/rollback status, timestamps, running state) of *any* stack in the installation by changing the `stack_id` in the request path/query. This is an unauthorized read of stack/deploy state across a boundary the token was explicitly created not to cross, matching the "unauthenticated/unauthorized read of stack state ... deploy output" High-impact category.

### Likelihood Explanation
Exploitation only requires possession of any valid, low-privilege `ApiClient` token that has `read:stack` permission (which is the normal, minimal permission most integrations request) — it does not require the `deploy:stack`, `write:stack`, or admin access. Because `Api::CCMenuUrlController` and `ApiClientsController` allow ordinary authenticated Shipit users to self-service create such scoped tokens (e.g. the "CCMenu Client"/API client creation flow shown in `app/views/shipit/api_clients/new.html.erb`), the ability to mint a legitimately-scoped low-privilege token and then use it outside its intended scope is realistic without any additional social engineering, secret theft, or session hijacking.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` collection instead of the raw `Stack` model, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
so a stack-scoped `ApiClient` can only ever resolve to its authorized stack, consistent with every other controller under `Api::BaseController`.

### Proof of Concept
1. As a normal Shipit user, create (or have created for you) an `ApiClient` with only the `read:stack` permission scoped to `Stack A` (`api_client.stack_id = A.id`).
2. Obtain the client's `authentication_token` (e.g. via the `api_clients#show` view / `api_client_token` helper).
3. Send `GET /api/stacks/<Stack B id-or-param>/ccmenu.xml?token=<token for the client scoped to Stack A>` (route defined under the `ccmenu` scope, handled by `Api::CCMenuController#show`, which calls `authenticate_api_client` using the `token` param and then `require_permission :read, :stack`).
4. The request succeeds and returns Stack B's CCMenu status/deploy data, even though the token's `ApiClient.stack_id` is Stack A's id — because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of the scoped `stacks.from_param!` used everywhere else in the API. [5](#0-4) [6](#0-5)

### Citations

**File:** app/controllers/shipit/api/base_controller.rb (L18-21)
```ruby
      class << self
        def require_permission(operation, scope, options = {})
          before_action(options) { require_permission!(operation, scope) }
        end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-84)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end

      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
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
  end
end
```

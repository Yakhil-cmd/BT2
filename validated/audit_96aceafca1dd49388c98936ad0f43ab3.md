### Title
CCMenu API endpoint bypasses ApiClient stack scoping, letting a stack-scoped token read any other stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` binds an `ApiClient`'s authority to a specific `Stack` via `current_api_client.stack_id`, and every properly-scoped controller resolves the acted-upon stack through the `stacks` relation, which filters by that binding: `stacks.from_param!(params[:id/stack_id])` [1](#0-0) . `Api::StacksController` follows this pattern correctly [2](#0-1) . However `Api::CCMenuController` overrides `stack` to load `Stack.from_param!(params[:stack_id])` directly, skipping the `stacks` scoping relation entirely [3](#0-2) , while still only requiring the unscoped permission check `require_permission :read, :stack` [4](#0-3) .

### Finding Description
The equality that should hold is: **the stack a token authorizes == the stack the request touches**. `ApiClient#check_permissions!` only checks that the client's `permissions` array contains `"read:stack"` — it never checks the caller-supplied `stack_id`/`params[:stack_id]` against `current_api_client.stack_id` [5](#0-4) . The scope enforcement is delegated entirely to the `stacks`/`stack` helper in `BaseController`, which is supposed to be the single choke point converting "any stack" params into "only the stack this client is scoped to" [1](#0-0) .

`CCMenuController` breaks this binding by defining its own `stack` method that calls `Stack.from_param!` on the raw class, ignoring the `stacks` scope derived from `current_api_client.stack_id` [6](#0-5) . Because `require_permission :read, :stack` before-action only calls `check_permissions!(:read, :stack)` (permission-name check, not stack-id check) [7](#0-6) , any `ApiClient` that merely has the `read:stack` permission bit — even one created and scoped to Stack A via the normal flow (`CCMenuUrlController#client`, which creates `ApiClient` with `permissions: %w[read:stack]` [8](#0-7) , or one scoped via the `api_client.stack` association shown in fixtures such as `here_come_the_walrus` [9](#0-8) ) — can supply an arbitrary `stack_id` on the CCMenu endpoint and read build/deploy state for a stack it was never authorized to see.

Before the attacker's request: token T is bound to stack A only (`api_client.stack_id == A.id`); T can only read `A`'s data through every endpoint that uses `stacks`. After the request: T, presented to `GET /api/1/stacks/:stack_id/ccmenu`, with `params[:stack_id] = B.id`, successfully renders `B`'s CCMenu XML (`stack.deploys_and_rollbacks.last`) because `CCMenuController#stack` never intersects `params[:stack_id]` with `current_api_client.stack_id`.

### Impact Explanation
This is a cross-stack authorization bypass: a legitimately-issued, stack-scoped credential (e.g. the `read:stack`-only CCMenu token that `CCMenuUrlController` mints for ordinary logged-in users [8](#0-7) ) can be replayed against `Api::CCMenuController#show` to obtain the last deploy/rollback status, running state, and project name of any stack in the installation, not just the one it was scoped/created for [10](#0-9) . This matches the "High" impact bucket: unauthenticated (here, cross-scope) read of stack state/deploy output across repositories that the token holder should not have access to, effectively defeating the per-stack authorization model that `ApiClient.stack_id` is meant to enforce.

### Likelihood Explanation
Likelihood is high given the vulnerability requires only possession of any valid `read:stack`-scoped `ApiClient` token — which is trivially self-issued by any authenticated Shipit user visiting a stack's CCMenu URL feature (`CCMenuUrlController#fetch`) [11](#0-10) . No special privilege, admin role, or webhook secret is needed; the attacker supplies their own `stack_id` in the URL to pivot to other stacks.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation, mirroring `Api::StacksController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This ensures `current_api_client.stack_id` (when present) is intersected with the requested `stack_id`, restoring the "token authorizes == stack touched" invariant, consistent with every other `Api::BaseController` subclass.

### Proof of Concept
1. As user `alice`, visit any stack `A`'s CCMenu URL feature; `CCMenuUrlController#fetch` creates/reuses an `ApiClient` named "CCMenu Client" with `permissions: ["read:stack"]` and returns `authentication_token` T embedded in a query string.
2. Using T via HTTP Basic Auth (or the `token` query param, both accepted by `CCMenuController#authenticate_api_client` [12](#0-11) ), send:
   `GET /api/1/stacks/<owner-B>/<name-B>/<environment-B>/ccmenu?token=T`
   where `B` is a stack `alice` (and the client that created T) has no relation to.
3. `require_permission :read, :stack` passes because T's `permissions` includes `read:stack`; `stack` resolves `B` directly via `Stack.from_param!`, bypassing any stack-id scoping, and the response renders `B`'s latest deploy/rollback status in the XML body [10](#0-9) .

### Citations

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

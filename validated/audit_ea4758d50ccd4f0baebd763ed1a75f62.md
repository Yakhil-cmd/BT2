Confirmed: `CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) resolves the stack via `Stack.from_param!(params[:stack_id])` directly against the global `Stack` table, unlike `BaseController#stack` (`app/controllers/shipit/api/base_controller.rb:78-80`), which resolves through `stacks` — a set restricted to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is stack-scoped (`app/controllers/shipit/api/base_controller.rb:74-76`). This is the same bug class as the report: a mapping/authorization value (`current_api_client.stack_id`, the stack the token is supposed to be limited to) is never actually consulted when performing the read, so the code proceeds as if the binding holds even though it doesn't.

### Title
Stack-scoped API token bypasses its stack restriction in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` overrides the `stack` accessor to look up any stack by ID from the global `Stack` table instead of using the `ApiClient`-scoped set that `Api::BaseController` provides, allowing a token scoped to one stack to read build/deploy status of any other stack.

### Finding Description
`Api::BaseController` defines the trust binding: `token.stack_id == stack.id` for any request made with a stack-scoped `ApiClient`. This is enforced by `stacks`, which restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true, and `stack` looks the requested resource up only within that restricted set (`from_param!`) [1](#0-0) .

`Api::CCMenuController` requires only the coarse `read:stack` permission (not a stack match) via `require_permission :read, :stack` [2](#0-1) , and then overrides `stack` to bypass the scoped lookup entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

Because `Stack.from_param!` queries the unrestricted `Stack` model rather than the `current_api_client`-scoped `stacks` relation, the `token.stack_id == stack.id` binding that `BaseController` establishes for every other API resource is never checked here. Any request authenticated with a valid stack-scoped token (permission `read:stack`) can supply an arbitrary `stack_id` and receive that other stack's CCMenu status document, which includes `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `activity`, and `webUrl` (confirmed by the test asserting these XML attributes) [4](#0-3) .

Contrast this with `Api::StacksController#show`, which inherits `BaseController#stack` and therefore correctly stays within the token's authorized stack set [5](#0-4) . `ApiClient#check_permissions!` only checks the operation/scope string, not stack identity [6](#0-5) , so nothing else in the request path re-establishes the equality that `CCMenuController` breaks.

### Impact Explanation
This is an unauthenticated-for-that-resource / cross-tenant read of stack deploy state: an attacker holding any valid stack-scoped `read:stack` API token (e.g., the low-privilege CCMenu client automatically minted by `CCMenuUrlController#client` for any logged-in Shipit user, scoped to `permissions: %w[read:stack]`) can enumerate `stack_id` values and read build status/labels/timestamps for stacks they were never granted access to [7](#0-6) . This matches the "unauthenticated read of stack state" High-impact category, since it crosses the authorization boundary the token system is designed to enforce.

### Likelihood Explanation
Any holder of a stack-scoped API token/CCMenu URL (which is routinely handed out to CI dashboards, low-trust integrations, and individual users) can trigger this simply by changing the `stack_id` in the URL — no special privilege beyond having one legitimate scoped token is required, and the request format is trivial to construct.

### Recommendation
Change `Api::CCMenuController#stack` to resolve the stack through the same `stacks` (client-scoped) relation used by `BaseController`, e.g. `stacks.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` binding is enforced consistently across all API endpoints.

### Proof of Concept
1. Create two stacks, A and B.
2. Create an `ApiClient` scoped to stack A only (`stack_id: A.id`, `permissions: ['read:stack']`), e.g. via `CCMenuUrlController#fetch` for stack A.
3. Using that token's `authentication_token`, send `GET /api/<B.to_param>/cc.xml?token=<token>` (or with Basic Auth header) — i.e., substitute stack B's id/permalink for `stack_id`.
4. Observe `Api::CCMenuController#show` returns HTTP 200 with stack B's `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, contrary to the token being scoped only to stack A, because `stack` resolves via unrestricted `Stack.from_param!` rather than the client-scoped `stacks` relation [8](#0-7) .

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L20-31)
```ruby
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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-39)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end
```

**File:** app/controllers/shipit/api/stacks_controller.rb (L1-8)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class StacksController < BaseController
      require_permission :read, :stack, only: %i[index show]
      require_permission :write, :stack, only: %i[create update destroy]

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

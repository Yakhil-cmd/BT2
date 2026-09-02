### Title
CCMenuUrlController mints a `read:stack` ApiClient token that is not scoped to any stack, and Api::CCMenuController accepts it for any stack - (File: app/controllers/shipit/ccmenu_url_controller.rb, app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::CCMenuUrlController#client` mints an `ApiClient` with `permissions: %w[read:stack]` via `ApiClient.create_with(...).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` but never sets `stack:`, so `client.stack_id` is `nil`. `Api::CCMenuController` accepts that token and, unlike `Api::BaseController#stack` (which scopes lookups through `stacks` → `current_api_client.stack_id? ? Stack.where(id: ...) : Stack.all`), it overrides `#stack` to do a raw `Stack.from_param!(params[:stack_id])`, so the unscoped `read:stack` permission check in `require_permission :read, :stack` (which only checks the permission string, not stack binding) lets the token read the CCMenu XML for **any** stack.

### Finding Description
The claimed binding, expressed as an equality that should hold but doesn't:

`token.stack_id == stack_id_embedded_in_the_generated_url`

- `CCMenuUrlController#fetch` (app/controllers/shipit/ccmenu_url_controller.rb:7-11) builds `uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))` and appends `client.authentication_token`.
- `CCMenuUrlController#client` (lines 15-18) creates the `ApiClient` via `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`. `ApiClient` has `belongs_to :stack, optional: true` (app/models/shipit/api_client.rb:8), and `create_with` never sets `stack:`, so `client.stack_id` is `nil` for every stack the user requests a CCMenu URL for. Because `find_or_create_by!` is keyed only on `creator` and `name`, this same single unscoped client is reused across every stack that user ever fetches a CCMenu URL for.
- `Api::BaseController#check_permissions!` (app/controllers/shipit/api/base_controller.rb:82-84) only checks `current_api_client.check_permissions!(operation, scope)`, i.e., it verifies the permission string `"read:stack"` is present — it performs no per-stack binding check at all. Stack binding is supposed to happen via `BaseController#stacks`/`#stack` (lines 74-80), which scope by `current_api_client.stack_id` when present, else fall back to `Stack.all`.
- `Api::CCMenuController` (app/controllers/shipit/api/ccmenu_controller.rb) declares `require_permission :read, :stack` but overrides `#stack` (lines 29-31) to call `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `stacks` scoping in `BaseController`. Since `client.stack_id` is nil anyway (this ApiClient was never bound to a stack), even the fallback `stacks` scoping in `BaseController` would have returned `Stack.all` for this client — the override in `CCMenuController` makes this doubly true.

Attacker flow: An authenticated low-privilege user visits `GET /stacks/:stack_id/ccmenu_url` for any stack they can view (this route only requires being logged in via `Shipit::Authentication`, not stack-specific authorization for issuing a CCMenu token). The response contains a `ccmenu_url` with a valid `token`. Because the underlying `ApiClient` has `permissions: ["read:stack"]` and no stack binding, the attacker can now call `GET /api/stacks/:any_other_stack_id/ccmenu_url.xml?token=<token>` for **any** stack id in the instance and receive the CCMenu XML (latest deploy id, status, `ended_at`) for stacks they were never authorized to view.

### Impact Explanation
The token exfiltrates deploy status/state for arbitrary stacks (`stack.deploys_and_rollbacks.last`), which is an unauthorized cross-tenant read of stack/task state — a real credential (a valid, reusable `ApiClient.authentication_token`) is minted with more scope than the requesting UI flow intended and then accepted for use against unrelated stacks. This matches "High - escalation ... unauthenticated/unauthorized read of stack state" per the given severity taxonomy: any user who can view one stack (or even a stack they nominally have some access to) obtains a durable API token effectively equivalent to a read-only, all-stacks API client, repeatable indefinitely with no signature/secret access.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs a logged-in Shipit session (which is the normal condition for "any current_user") and access to visit `/stacks/:stack_id/ccmenu_url` for at least one stack. No GitHub secrets, webhook signing keys, or admin/maintainer roles are required. The resulting token is durable (stored `ApiClient` row, `find_or_create_by!`-cached) and can be replayed against the `/api/stacks/:id/ccmenu_url.xml` endpoint for arbitrary stack ids at any time. This is fully reproducible with a controller/unit test and does not require any live GitHub interaction.

### Recommendation
- In `CCMenuUrlController#client`, set `stack:` on the created `ApiClient` (e.g., `ApiClient.create_with(permissions: %w[read:stack], stack: stack).find_or_create_by!(creator: current_user, stack: stack, name: 'CCMenu Client')`), so each token is bound to a single stack.
- In `Api::CCMenuController`, remove the `#stack` override and rely on `Api::BaseController#stack`/`#stacks`, so the stack lookup is scoped by `current_api_client.stack_id` when present, preventing any unscoped `ApiClient` from reading arbitrary stacks.

### Proof of Concept
```ruby
# test/controllers/ccmenu_controller_test.rb (extend existing test file)
test ":fetch mints an ApiClient not bound to the requested stack" do
  get :fetch, params: { stack_id: @stack.to_param }
  client = ApiClient.last
  assert_nil client.stack_id, "expected ApiClient to have no stack binding (demonstrates the bug)"
end

test "token minted for one stack can read a different stack's ccmenu xml" do
  other_stack = shipit_stacks(:cyclimse) # any other fixture stack
  get :fetch, params: { stack_id: @stack.to_param }
  data = JSON.parse(response.body)
  token = Rack::Utils.parse_nested_query(URI(data['ccmenu_url']).query)['token']

  @controller = Shipit::Api::CCMenuController.new
  get :show, params: { stack_id: other_stack.to_param, token: token }, format: :xml
  assert_response :ok # should be :forbidden/:not_found if properly scoped
end
```
Both assertions demonstrate the broken binding: the `ApiClient` has no `stack_id`, and the token minted for `@stack` is accepted for `other_stack`. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/models/shipit/api_client.rb (L7-9)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

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

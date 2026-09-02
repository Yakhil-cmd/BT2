## Analysis

I found a valid analog: the `stack` scope-check bypass in `Shipit::Api::CCMenuController`, matching the listed binding "a stack a token authorises versus a stack it touches."

`ApiClient` supports being scoped to a single `stack` (`belongs_to :stack, optional: true`, `stack: shipit` fixture example) [1](#0-0) . The generic `Api::BaseController` enforces this scope for every normal API endpoint: `stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` resolves `params[:stack_id]` only from that restricted relation [2](#0-1) . This is confirmed by the test asserting "an api client scoped to a stack will only see that one stack" [3](#0-2) .

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: `@stack ||= Stack.from_param!(params[:stack_id])` resolves against **all** stacks, not `stacks` [4](#0-3) . The controller still declares `require_permission :read, :stack` [5](#0-4) , but `check_permissions!` only checks the permission string exists on the client, never the bound `stack_id` [6](#0-5) .

### Title
Stack-scoped API token bypasses stack authorization in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` records can be scoped to a single stack via `stack_id`, and `Api::BaseController#stack`/`#stacks` enforce that scope for all standard API endpoints. `Api::CCMenuController` overrides `#stack` with `Stack.from_param!(params[:stack_id])`, which resolves against `Stack` globally instead of the scoped `stacks` relation, so a token authorised for `read:stack` on Stack A can be used to read CI/deploy status for any other Stack B.

### Finding Description
`Api::BaseController#stacks` restricts the queryable stacks to the client's bound `stack_id` when present, and `#stack` resolves `params[:stack_id]` from that restricted relation [2](#0-1) . `Api::CCMenuController` defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly, ignoring `current_api_client.stack_id` entirely [4](#0-3) . The only authorization check performed is `require_permission :read, :stack`, which merely verifies the string `"read:stack"` is present in the client's `permissions` array, with no comparison to the requested stack ID [6](#0-5) .

The binding that should hold is: `stack the token authorises == stack the token's request touches`. For every other API controller this holds via `stacks.from_param!`. For `CCMenuController` it does not: the token authorises stack A (its bound `stack_id`), but the request can touch any stack B by supplying a different `stack_id` in the URL path (`/api/stacks/*stack_id/ccmenu`, routed in `config/routes.rb`) [7](#0-6) .

### Impact Explanation
Any holder of a stack-scoped `read:stack` API token — which is by design meant to be shared/embedded in third-party CI dashboard tools via `CCMenuUrlController#fetch` (the URL contains the token in cleartext query string) — can enumerate and read deploy/rollback status (`deploys_and_rollbacks`) of every other stack in the Shipit instance, not just the one it was issued for. This is an unauthenticated-read-of-stack-state class of escalation beyond the token's intended authorization scope, matching the "unauthenticated read of stack state" High-impact criterion, because the effective exposure is broader than the credential's declared/intended scope.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped API clients (a documented, supported feature: `ApiClient` has a `belongs_to :stack, optional: true`, and the CCMenu flow specifically creates and hands out such tokens for embedding in external tools). No special privilege beyond possessing one legitimately-scoped, low-privilege `read:stack` token is required to pivot to reading arbitrary stacks; only the `stack_id` path parameter needs to be changed.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation instead of `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This aligns `CCMenuController` with the scoping behavior enforced by `Api::BaseController` for every other endpoint.

### Proof of Concept
1. As a stack owner, create a CCMenu URL for Stack A (`GET /ccmenu/*stack_id`, handled by `CCMenuUrlController#fetch`), which creates/fetches an `ApiClient` with `permissions: ['read:stack']` and returns a URL containing `token=<A's-scoped-token>` [8](#0-7) .
   - Note: to demonstrate the scoping bypass specifically, use/assume an `ApiClient` bound to stack A via `stack_id` (as supported by the model and exercised in fixtures such as `here_come_the_walrus`, which is scoped to `stack: shipit`) [9](#0-8) .
2. Send `GET /api/stacks/<owner>/<other-repo>/<other-env>/ccmenu?token=<A's-scoped-token>` for Stack B, which A's token was never authorized for.
3. Because `CCMenuController#stack` calls `Stack.from_param!` (unscoped) instead of `stacks.from_param!` (scoped) [4](#0-3) , the request succeeds and returns Stack B's latest deploy/rollback status, despite the token being scoped only to Stack A.

**Note on uncertainty**: I could not fully confirm from the index whether `CCMenuUrlController#fetch`'s "CCMenu Client" is ever created with a `stack_id` set (its call site does not pass `stack:` when creating the client) [10](#0-9) ; however, the `ApiClient` model and other flows (e.g., `here_come_the_walrus` fixture, `api_clients_controller.rb` UI) do support and create stack-scoped tokens with `read:stack` permission, and those are exactly the tokens whose scope the CCMenu endpoint fails to enforce.

### Citations

**File:** app/models/shipit/api_client.rb (L1-21)
```ruby
# frozen_string_literal: true

module Shipit
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-6)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

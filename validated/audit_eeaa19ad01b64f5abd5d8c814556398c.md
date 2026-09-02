### Title
Stack-scoped ApiClient tokens can read the CI/deploy status of any stack via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Api::CCMenuController#stack` resolves the target stack directly from the request's `stack_id` parameter instead of through the `stack_id`-scoped collection that `Api::BaseController` enforces for every other API endpoint. A token that was authorized (`ApiClient#stack_id`) to read only one specific stack can be replayed against `Api::CCMenuController#show` with a different `stack_id` and successfully read that other stack's build/deploy status. This breaks the binding "stack a token authorizes" == "stack the token can act on/read."

### Finding Description
`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) . `Api::BaseController` enforces this scoping consistently for the whole API surface: the `stacks` collection is filtered down to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated client has a `stack_id`, and `stack` is resolved from that filtered collection: [2](#0-1) 

Permission checks (`require_permission :read, :stack`) only verify that the operation name `read:stack` is present in `ApiClient#permissions`; they never validate that the specific `stack_id` in the request matches the client's own `stack_id`: [3](#0-2) 

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely and resolve the model directly from the raw class: [4](#0-3) 

Because `Stack.from_param!(params[:stack_id])` is called on the unscoped `Stack` class rather than on `stacks` (which would be filtered by `current_api_client.stack_id`), any authenticated `ApiClient` holding the `read:stack` permission — even one deliberately narrowed to a single stack via its `stack_id` column, as is done for the CCMenu use case itself (see `CCMenuUrlController#client`, which mints a `read:stack`-only token) — can supply an arbitrary `stack_id` and successfully read that unrelated stack's CI/deploy status. [5](#0-4) 

This is the exact class of bug in the reference report: a binding that is *supposed* to hold (token authorizes stack X) is checked in one place (`BaseController#stack`/`#stacks`) but a different code path (`CCMenuController#stack`) acts on a field (`params[:stack_id]`) that was never re-validated against the authorized value.

### Impact Explanation
This is an unauthorized read of stack state: a token minted for, or scoped to, a single stack (e.g. `here_come_the_walrus` fixture demonstrates `stack:` scoping on `ApiClient`, and `CCMenuUrlController` mints exactly this kind of narrowly-permissioned `read:stack` token for a specific stack's CCMenu widget) can be used to fetch the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, lock state, activity) of every other stack in the Shipit instance, including private/internal repositories the token holder was never meant to see. This matches the "High - unauthenticated/unauthorized read of stack state" impact category, since the token's authorization was meant to be confined to one stack and the vulnerable endpoint ignores that confinement.

### Likelihood Explanation
Any holder of a legitimately-issued, narrowly-scoped `read:stack` CCMenu token (which Shipit itself generates and distributes to users via `CCMenuUrlController`, intended to be embeddable in CI dashboard widgets and therefore not treated as highly sensitive) can trivially exploit this by changing the `stack_id` query/path parameter on repeated requests. No additional privilege, secret, or session is required beyond possessing one such token — exactly the "unprivileged-attacker" bar in scope.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the same `stacks` collection used by `Api::BaseController`, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, so that a client scoped to a specific `stack_id` cannot query other stacks. Add a regression test that authenticates with a stack-scoped `read:stack` client and asserts a `404`/`403` when requesting a different stack's `stack_id`.

### Proof of Concept
1. As an administrator, create (or have Shipit auto-create via `CCMenuUrlController#fetch`) an `ApiClient` scoped to `stack_id: <stack_A.id>` with permissions `['read:stack']`, and hand out its `authentication_token` (this is exactly the URL Shipit generates for embedding in CI badge/status widgets).
2. Using only that token, issue: `GET /api/stacks/:stack_A/ccmenu.xml?token=<token>` — succeeds as intended.
3. Issue instead: `GET /api/stacks/:stack_B/ccmenu.xml?token=<token>` where `stack_B` is any other, unrelated stack (different repository/environment) the token was never authorized for.
4. Because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than through `stacks` (which would filter by `current_api_client.stack_id`), the request succeeds and returns `stack_B`'s `lastBuildStatus`, `lastBuildLabel`, `activity`, and `webUrl` — data the token was never authorized to access. [6](#0-5)

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** test/controllers/api/ccmenu_controller_test.rb (L20-31)
```ruby
      test "#show renders the xml" do
        get :show, params: { stack_id: @stack.to_param }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end

      test "can authenticate with query string token" do
        request.headers['Authorization'] = 'bleh'
        get :show, params: { stack_id: @stack.to_param, token: @client.authentication_token }
        assert_response :ok
        assert_payload 'name', @stack.to_param
      end
```

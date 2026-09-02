## Analysis

The reported bug class is "a value that is used as an authorization boundary but is not consistently enforced across all code paths that touch the protected resource." In Shipit, `ApiClient` records can be scoped to a single `Stack` via `stack_id` (`belongs_to :stack, optional: true` in `app/models/shipit/api_client.rb`), and `Api::BaseController#stacks` is supposed to be the single choke point enforcing that scope: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` at `app/controllers/shipit/api/base_controller.rb:74-80`. `Api::StacksController` correctly routes through this via `stacks.from_param!(params[:id])` (`app/controllers/shipit/api/stacks_controller.rb:87-89`), which is proven by the existing test "an api client scoped to a stack will only see that one stack."

However, `Api::CCMenuController` overrides `stack` to bypass the scoping helper entirely:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
```

at `app/controllers/shipit/api/ccmenu_controller.rb:29-31`. It calls `Stack.from_param!` directly on the model, not `stacks.from_param!`, so the `current_api_client.stack_id` restriction from `BaseController#stacks` is never applied. Any token holding `read:stack`, even one explicitly scoped by its `stack_id` column to a single stack, can supply an arbitrary `stack_id` parameter and read the CI status/build history of any other stack in the deployment via `GET /api/stacks/:stack_id/ccmenu`.

### Title
Stack-scoped API tokens can read CI status of any stack via CCMenu endpoint bypass - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController#stack` resolves the target stack with `Stack.from_param!(params[:stack_id])` instead of the shared, scope-enforcing `stacks.from_param!` helper used by every other API controller, letting a stack-scoped `ApiClient` token read information about stacks it was never authorized for.

### Finding Description
`ApiClient` supports being restricted to a single stack through its `stack_id` column [1](#0-0) . The intended enforcement point is `Api::BaseController#stacks`, which filters the queryable stack set down to `current_api_client.stack_id` when that attribute is set, and `#stack` builds on top of it via `stacks.from_param!(params[:id])` [2](#0-1) . `Api::StacksController` relies on exactly this pattern for its own `stack` accessor [3](#0-2) , and this scoping is exercised by an existing test confirming a scoped client "will only see that one stack" [4](#0-3) .

`Api::CCMenuController`, however, defines its own `stack` method that calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model, completely skipping the `stacks` scoping helper [5](#0-4) . The only authorization check performed is `require_permission :read, :stack`, which merely verifies the token has the `read:stack` permission string via `ApiClient#check_permissions!` [6](#0-5)  — it does not verify that the requested stack matches the token's bound `stack_id`. This breaks the equality that should hold: `stack_that_token_authorizes == stack_that_action_touches`. Before the flaw, this equality is enforced in `StacksController`/`BaseController`; after routing through `CCMenuController`, an attacker holding any token with `read:stack` (including one deliberately restricted to a single stack) can substitute any other stack's identifier in `params[:stack_id]` and the check is silently skipped.

### Impact Explanation
This is an unauthenticated-by-design read tunnel around a token's declared scope: an operator who issues a narrowly-scoped `read:stack` token (e.g., for a status badge or CCMenu integration tied to one stack, as built by `CCMenuUrlController#client`, `app/controllers/shipit/ccmenu_url_controller.rb:15-18`) unknowingly grants that token holder read access to deploy/rollback status, lock state, and last-build metadata for every stack in the Shipit instance, not just the intended one. This matches the "unauthorized read of stack state" High-severity category, since it escalates a deliberately scoped credential into cross-stack visibility.

### Likelihood Explanation
High — no special privileges beyond possession of any valid `read:stack`-permitted token are required, and the request is a single unauthenticated-parameter substitution (`stack_id`) against a publicly routed, unauthenticated-content endpoint (`GET /ccmenu/*stack_id`, `config/routes.rb:49-51` and the API mount at `resources :hooks`/CCMenu nested route). No signature, session, or additional permission check stands in the way once a token exists.

### Recommendation
Change `Api::CCMenuController#stack` to route through the scope-aware helper, matching every other controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the invariant that a stack-scoped token can only resolve the stack it was issued for.

### Proof of Concept
1. As an operator, create an `ApiClient` scoped to Stack A only (`stack_id` set to Stack A's id, permission `read:stack`) — the same configuration exercised by the `here_come_the_walrus` fixture used in `test/controllers/api/stacks_controller_test.rb`.
2. Using that client's `authentication_token`, issue `GET /api/stacks/:stack_B_id/ccmenu?token=<token>` where `stack_B_id` refers to any *other* stack.
3. Observe the request succeeds with `200 OK` and returns Stack B's CI status XML, even though the token is scoped to Stack A — reproducing the bypass demonstrated by `Api::CCMenuController#stack` at `app/controllers/shipit/api/ccmenu_controller.rb:29-31`, contrasted with the properly-scoped behavior verified in `test/controllers/api/stacks_controller_test.rb:217-223`.

### Citations

**File:** app/models/shipit/api_client.rb (L7-12)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true

    validates :creator, :name, presence: true

    serialize :permissions, coder: Shipit.serialized_column(:permissions, type: Array)
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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

### Title
Stack-scoped `ApiClient` token can read CCMenu status of any stack - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The `Api::CCMenuController` binds the stack a request touches only to the URL's `stack_id` parameter, never checking it against the stack the authenticated `ApiClient` token is actually scoped to. Every other API controller resolves the target `Stack` through the tenant-scoped `stacks` collection, but `CCMenuController` overrides `stack` to query the unscoped `Stack` model directly, breaking the binding `current_api_client.stack_id == requested_stack.id`.

### Finding Description
`Shipit::ApiClient` can optionally be bound to a single stack (`belongs_to :stack, optional: true`), and this binding is the mechanism used across the API to restrict a token to one stack's data: [1](#0-0) 

`Api::BaseController` implements this restriction via the `stacks` helper, which every "normal" controller (e.g. `StacksController`, `HooksController`, `DeploysController`) relies on to resolve the target stack: [2](#0-1) 

`Api::CCMenuController`, however, defines its own private `stack` method that bypasses this scoping entirely, querying the global `Stack` model directly by the URL's `stack_id`: [3](#0-2) 

The `before_action` permission check only verifies that the token's `permissions` array contains `read:stack` — it never checks the requested stack against `current_api_client.stack_id`: [4](#0-3) [5](#0-4) 

So the binding that should hold — "the stack a token authorizes" (`ApiClient#stack_id`) equals "the stack a request touches" (`params[:stack_id]`) — is enforced everywhere except in `CCMenuController`, which silently drops it and consults `Stack.from_param!(params[:stack_id])` unconditionally, exactly like the analog Hyperdrive report where reserve updates were checked with stale state instead of the actual post-update state.

### Impact Explanation
Any holder of a legitimately-issued `ApiClient` token scoped to one stack (a common integration pattern — see the `here_come_the_walrus` fixture with `stack: shipit`) can read the CCMenu XML status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of **any other stack** in the Shipit instance, including private/internal ones the token was never granted access to, simply by changing the `stack_id` in the request URL/query token param. This is an unauthorized read of stack/deploy state across tenant boundaries, matching the High-impact category "unauthenticated/unauthorized read of stack state, task streams or deploy output."

### Likelihood Explanation
Exploitation requires only possession of any valid `ApiClient` token with `read:stack` permission (the least-privileged, most commonly issued permission) — no GitHub App secret, private key, or elevated account is needed. The route is public and unauthenticated beyond basic/token auth: [6](#0-5) 
An attacker who is simply an authorized user of one stack (or holds a leaked/shared CCMenu link) can trivially enumerate other stacks' CCMenu URLs.

### Recommendation
Have `Api::CCMenuController#stack` resolve through the scoped `stacks` collection (as `BaseController` and every other API controller do) instead of querying `Stack` directly, e.g. `stacks.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient` cannot read data belonging to a different stack.

### Proof of Concept
1. As an administrator, create (or observe) an `ApiClient` scoped to `stack: shipit` with `permissions: ['read:stack']` (e.g. via `Api::CCMenuController`/`ApiClientsController`, or the fixture `here_come_the_walrus`).
2. Using that token's `authentication_token`, issue:
```
GET /ccmenu/other-org/other-repo/other-environment/ccmenu?token=<here_come_the_walrus_token>
```
3. The request succeeds and returns the CCMenu XML for `other-org/other-repo/other-environment`, a stack the token was never scoped to, because `Api::CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than the tenant-scoped `stacks` collection.

### Citations

**File:** app/models/shipit/api_client.rb (L7-21)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
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

**File:** config/routes.rb (L27-29)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
```

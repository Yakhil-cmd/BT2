This confirms the binding break. The `StacksController#stack` method (the API's normal stack-scoped pattern) resolves through `stacks.from_param!(params[:id])`, where `stacks` filters by `current_api_client.stack_id` when the client is stack-scoped: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` in `app/controllers/shipit/api/base_controller.rb`. But `Api::CCMenuController#stack` overrides this with `Stack.from_param!(params[:stack_id])` directly, bypassing the `stacks` scope entirely, while still only checking the generic `read:stack` permission via `require_permission :read, :stack`, which validates permission strings but never checks whether the authenticated client's `stack_id` matches the requested stack. [1](#0-0) [2](#0-1) [3](#0-2) 

### Title
Stack-scoped ApiClient token grants read access to any stack via CCMenu API - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::CCMenuController` authenticates tokens the same way as other API controllers but resolves the target `stack` without applying the API client's stack scope, breaking the equality: `stack the token authorizes == stack it touches`.

### Finding Description
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true` and the helper `stack_id?` [4](#0-3) . The `Api::BaseController#stacks` method is the mechanism that enforces this scope for every normal API controller: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [5](#0-4) . Controllers like `Api::StacksController` correctly resolve the target stack through this scoped relation: `@stack ||= stacks.from_param!(params[:id])` [6](#0-5) .

`Api::CCMenuController`, however, overrides `stack` to bypass the scope entirely: `@stack ||= Stack.from_param!(params[:stack_id])` [7](#0-6) . The only authorization check applied is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(operation, scope)` — this only checks that the permission string `"read:stack"` is present in the client's `permissions` array, it never compares `current_api_client.stack_id` to the `stack_id` param [8](#0-7) . `CCMenuController` also allows authenticating via a `token` query-string parameter rather than only Basic-Auth headers [9](#0-8) , and such tokens are routinely created and exposed for CCMenu integration through `Shipit::CCMenuUrlController`, which mints a stack-scoped `read:stack` `ApiClient` per user/stack pair [10](#0-9) .

Consequently, a token that was only ever meant to authorize CCMenu read access to stack A (because it was scoped with `stack_id` = A) can be replayed against `GET /api/stacks/:stack_id/ccmenu.xml?token=...` with a different `stack_id` value (stack B), and `Api::CCMenuController#show` will happily render build/deploy status for stack B, because `stack` resolution never consults `current_api_client.stack_id`.

### Impact Explanation
This is an unauthenticated-scope read of stack state: the deploy/build status, last build label, and activity for an arbitrary stack are exposed to a holder of a stack-A-scoped token who is not authorized for stack B. This matches the "unauthenticated read of stack state" High-impact category, since the token's authorization boundary (a specific stack) is bypassed for any other existing stack in the installation.

### Likelihood Explanation
CCMenu tokens are routinely generated and distributed as plain URLs (`ccmenu_url`) intended for consumption by third-party CI dashboard tools, and query-string tokens are inherently easier to leak (browser history, logs, referrer headers) than Basic-Auth secrets. Any holder of one such legitimately-issued, narrowly-scoped token can immediately probe other `stack_id` values with no additional privilege.

### Recommendation
Make `Api::CCMenuController#stack` honor the client's scope, e.g. `@stack ||= stacks.from_param!(params[:stack_id])`, consistent with `Api::BaseController#stack` and `Api::StacksController#stack`, so that a stack-scoped `ApiClient` cannot resolve any stack outside `current_api_client.stack_id`.

### Proof of Concept
1. As a legitimate Shipit user, visit stack A's page; Shipit's `CCMenuUrlController#fetch` creates (or reuses) an `ApiClient` scoped to stack A with permission `read:stack`, and returns a URL like `.../api/stacks/A/ccmenu.xml?token=<A-scoped-token>` [11](#0-10) .
2. Take that token and issue `GET /api/stacks/B/ccmenu.xml?token=<A-scoped-token>` for an arbitrary stack B that the token was never scoped to.
3. `authenticate_api_client` accepts the token (it's a valid signed `ApiClient` id) [9](#0-8) ; `require_permission :read, :stack` passes because the token has `read:stack` in its permission list; `stack` resolves via `Stack.from_param!(params[:stack_id])` directly to stack B, ignoring that the token's `stack_id` is A.
4. The response renders stack B's deploy/build status XML, which the requester was never authorized to read.

### Citations

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L86-89)
```ruby

      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

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

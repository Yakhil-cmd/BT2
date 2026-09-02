## Finding

### Title
API token scoped to a single stack can read CI/deploy status of any other stack via the CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
The report's bug class is a value that is verified once (dMute delegation balance at staking) but never re-checked against the invariant it's supposed to enforce (long-term holding), letting an attacker "borrow" it for a single check. The engine analog is an `ApiClient` token whose *authorization scope* (`stack_id`) is checked in the generic `BaseController`, but a subclass controller re-implements the accessor and skips that scope check entirely, letting the token act on a stack it was never authorized for.

### Finding Description
`Shipit::Api::BaseController` scopes any stack lookup to the token's authorized stack: [1](#0-0) 

`ApiClient#stack_id` is an optional scoping field: when present, the client should only ever be able to act on that one stack (see the `here_come_the_walrus` fixture and its associated tests confirming `#index returns a list of stacks filtered by ... api client`): [2](#0-1) 

However, `Shipit::Api::CCMenuController` overrides `stack` and looks the stack up directly by param, bypassing the `stacks` scoping method entirely: [3](#0-2) 

The permission check enforced before the action only validates the *permission list* (`read:stack`), not the *stack scope*: [4](#0-3) [5](#0-4) 

So the binding that should hold — "the stack a token authorises == the stack it touches" — is broken specifically in this controller: a stack-scoped token authorized only for stack A can supply `stack_id=B` and successfully read stack B's latest deploy/rollback status, lock state, and build activity.

This is made worse by the fact that CCMenu additionally accepts the token as a plain query-string parameter instead of requiring HTTP Basic auth, and that URL is generated and persisted for users via `CCMenuUrlController`: [6](#0-5) [7](#0-6) 
This increases the likelihood that such a token leaks (browser history, CI dashboard bookmarks, logs) and is then usable, out of scope, against other stacks.

### Impact Explanation
An attacker holding (or having leaked) an `ApiClient` token that was deliberately scoped to a single stack can use it to read the deploy/rollback/lock status of any stack in the installation by simply changing the `stack_id` query parameter against the CCMenu endpoint. This is an unauthorized read of stack state that the token owner never granted, matching the "High - unauthenticated/unauthorized read of stack state" impact category.

### Likelihood Explanation
Exploitation requires only a valid, stack-scoped `ApiClient` token (already a normal, low-privilege credential meant for embedding in third-party CI dashboard tools such as CCMenu clients) and knowledge/guessing of another stack's `to_param` (repo/environment/branch identifier), which is not secret. No signature forgery, no elevated permission, and no session is needed — just calling the existing `GET /api/:stack_id/ccmenu.xml?token=...` route with a different `stack_id`.

### Recommendation
Remove the `stack` override in `Shipit::Api::CCMenuController` (or reimplement it to delegate to the inherited `stacks` scoping helper) so that stack lookups always go through `current_api_client.stack_id`-aware scoping, consistent with every other API controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. Create (or obtain) a stack-scoped `ApiClient` with `permissions: ['read:stack']` and `stack_id` set to stack A (e.g. the `here_come_the_walrus` fixture pattern).
2. Call `GET /api/<stack_B_param>/ccmenu.xml?token=<client.authentication_token>` where stack B is a different stack than the one the token is scoped to.
3. Observe the response returns HTTP 200 with stack B's deploy/rollback/lock state, even though the token's `stacks` scope (as enforced in `BaseController#stacks`) should have restricted it to stack A only — demonstrated by `CCMenuController#stack` at [8](#0-7)  never consulting `stacks`/`stack_id?`.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

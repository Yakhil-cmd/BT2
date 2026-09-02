### Title
Stack-scoped ApiClient tokens can read any stack's build status via CCMenuController - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack directly from `Stack.from_param!(params[:stack_id])` instead of going through `BaseController#stacks`, which is the method that enforces the binding between an `ApiClient` and the single stack it is scoped to. As a result, a token created with `stack_id` set (i.e. authorised for exactly one stack) can be replayed against the CCMenu endpoint with an arbitrary `stack_id` and successfully read that other stack's build/deploy state.

### Finding Description
`Shipit::Api::BaseController` defines the intended trust binding between an `ApiClient` and the stacks it may act on: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the client is scoped, and `stack` (used by every other API controller, e.g. `Api::StacksController`, `Api::TasksController`) is built on top of that scoped relation.

`Api::CCMenuController` overrides `stack` and bypasses this scoping entirely: [2](#0-1) 

The class-level `require_permission :read, :stack` declaration only checks that the token carries the `read:stack` permission string via `ApiClient#check_permissions!`: [3](#0-2) 

It never checks whether `current_api_client.stack_id` matches the requested `params[:stack_id]`. Because `#stack` in `CCMenuController` queries `Stack.from_param!` directly (the unscoped model, not the `stacks` scoped relation), any token holding `read:stack` — even one explicitly scoped to a single stack by `ApiClient.stack_id` — can retrieve the CI/build status XML of any stack in the installation by simply supplying a different `stack_id` in the URL.

This mirrors the reported bug class: a check is performed (`require_permission`/`check_permissions!`, analogous to the `balanceOf`/max-cap check) but the state actually acted upon (`stack`, analogous to `_to`'s token balance) is fetched through a path that never re-validates the binding the check was meant to enforce — the stack a token authorises versus the stack it touches.

### Impact Explanation
This breaks the binding "a stack a token authorises versus a stack it touches." An `ApiClient` that was deliberately scoped to a single stack — e.g. to give a monitoring tool minimal access to one project — can instead read status/build information (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, etc.) for every stack managed by the Shipit installation. This is an authorization-scope escalation that discloses stack state the token holder was never authorised to see, aligning with the "unauthenticated/unauthorized read of stack state" impact category.

### Likelihood Explanation
Any holder of a valid, stack-scoped `ApiClient` token (which can be self-service created by any authenticated user via `CCMenuUrlController#fetch`, itself scoped `permissions: %w[read:stack]`) can trigger this simply by changing the `stack_id` route/query parameter — no special privileges, timing, or race conditions are required. [4](#0-3) 

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that a stack-scoped `ApiClient` cannot resolve a stack outside of its authorised `stack_id`.

### Proof of Concept
1. As an authenticated user, hit `CCMenuUrlController#fetch` for `stack_A`; this creates/returns an `ApiClient` named "CCMenu Client" with `permissions: ['read:stack']` and no explicit `stack` restriction unless one is later set via the API client management UI to scope it to `stack_A` (`ApiClient#stack_id`).
2. Confirm the token only carries `read:stack` and `stack_id == stack_A.id`.
3. Call `GET /api/:stack_B_id/cause_ccmenu.xml?token=<token>` using `stack_B`'s param instead of `stack_A`'s.
4. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])`, which ignores `current_api_client.stack_id`, and returns `stack_B`. The response renders `stack_B`'s deploy/build status even though the token was only meant to authorise `stack_A`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

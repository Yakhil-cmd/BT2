### Title
Stack-scoped API tokens can read the CCMenu status of any stack, bypassing their `stack_id` scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` accessor used by `BaseController` to enforce token-to-stack scoping, replacing it with an unscoped `Stack.from_param!` lookup. An `ApiClient` token that is authorized only for one stack (`stack_id`) can therefore be used to read the CI/deploy status of any other stack, breaking the binding "the stack a token authorises == the stack it touches."

### Finding Description
`Shipit::Api::BaseController` defines a `stacks` scope that filters by the authenticated `ApiClient`'s `stack_id` when present: [1](#0-0) 

This scoped accessor is what `Api::StacksController#stack` correctly relies on: [2](#0-1) 

However, `Api::CCMenuController` redefines `stack` to bypass this scoping entirely, resolving directly against the global `Stack` relation using an attacker-supplied `stack_id` param: [3](#0-2) 

The controller only checks that the `ApiClient` has the generic `read:stack` permission (`require_permission :read, :stack`), it never checks that the requested stack matches the client's `stack_id`: [4](#0-3) [5](#0-4) 

Authentication for this controller can also be done purely via a `token` query-string parameter (no `X-Shipit-User` header, no session), so the token alone is the full authorization boundary being bypassed: [6](#0-5) 

Every other API resource that is meant to be scoped to a single stack (e.g. `Api::HooksController`) correctly derives its scope from `stack.id`, going through the scoped `stack` method inherited from `BaseController`: [7](#0-6) 

This confirms `CCMenuController` is the outlier that breaks the intended `ApiClient.stack_id` binding.

**Equality that should hold, and is broken:**
`stack a token is scoped to (ApiClient#stack_id)` == `stack the token can act on / read (params[:stack_id] resolved in CCMenuController#stack)`

Before the flaw (as in `StacksController`): the two sides are enforced equal via `stacks.from_param!`.
After the flaw (`CCMenuController`): the right-hand side is resolved from `Stack.from_param!` against all stacks, independent of `stack_id`, so the equality no longer holds.

### Impact Explanation
This is an unauthenticated-relative-to-target-stack read of stack state: an `ApiClient` token created with `read:stack` permission and scoped to Stack A can be replayed against `/api/1/stacks/:stack_id/ccmenu.xml` with `stack_id` set to Stack B, and successfully retrieve Stack B's latest deploy/rollback status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, activity, lock state) — data belonging to a stack the token was never authorized to see. This matches the in-scope High-severity category "unauthenticated read of stack state, task streams or deploy output," since it is effectively unauthenticated with respect to the target stack (the token only proves identity/permission-class, not stack scope).

### Likelihood Explanation
Low precondition burden: any holder of a stack-scoped `read:stack` token (e.g. the CCMenu token auto-created by `CCMenuUrlController#fetch`, which is explicitly `create_with(permissions: %w[read:stack])` and tied to one stack) can trivially probe other `stack_id` values, since stack ids/slugs are low-entropy and often guessable/enumerable, and no cross-stack check exists. No privileged access or session compromise is needed beyond possessing one legitimately-issued, narrowly-scoped token. [8](#0-7) 

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` accessor (as `StacksController` and `HooksController` do), i.e. `stacks.from_param!(params[:stack_id])`, so that a token scoped to `stack_id` cannot resolve any other stack. Add a regression test asserting that a stack-scoped `ApiClient` receives a 404/403 when hitting `ccmenu.xml` for a different stack.

### Proof of Concept
1. Visit `GET /stacks/:owner/:repo/:branch/ccmenu_url` (or otherwise obtain) a CCMenu token for Stack A; this creates an `ApiClient` with `permissions: ["read:stack"]` and `stack_id = A.id`.
2. As the attacker holding that token, request `GET /api/1/stacks/:B_id_or_slug/ccmenu.xml?token=<token-for-A>` where `B` is a different stack the attacker is not authorized to view.
3. `CCMenuController#authenticate_api_client` authenticates successfully via `ApiClient.authenticate(params[:token])`.
4. `require_permission :read, :stack` passes because the client has `read:stack` in its permission list — it does not check `stack_id`.
5. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` against the global `Stack` table, returning Stack B regardless of the token's `stack_id`.
6. The response renders Stack B's deploy/rollback status, leaking data outside the token's intended scope.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-31)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L50-52)
```ruby
      def stack_id
        stack.id if params[:stack_id].present?
      end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

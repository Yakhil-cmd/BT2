Confirmed: the CCMenu API route `GET /api/stacks/*stack_id/ccmenu` accepts an arbitrary `stack_id` param, and `Shipit::Api::CCMenuController` resolves `stack` via `Stack.from_param!(params[:stack_id])` [1](#0-0)  instead of going through the base class's scoped accessor `stacks.from_param!(params[:stack_id])`, which restricts to `Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped [2](#0-1) .

### Title
CCMenu API bypasses ApiClient stack scoping, allowing a stack-scoped token to read any stack's build state - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
An `ApiClient` can be created scoped to a single stack (`belongs_to :stack, optional: true`) [3](#0-2) , and this is exactly the intended use for the CCMenu integration: `CCMenuUrlController#client` creates/finds an `ApiClient` with only `read:stack` permission, implicitly meant for that one stack's dashboard, and generates a signed token embedding only the client id (not the stack) [4](#0-3) . The base API controller enforces this scoping for every other stack-scoped endpoint by resolving `stack` through `stacks.from_param!`, where `stacks` is filtered to `Stack.where(id: current_api_client.stack_id)` if the client is scoped [2](#0-1) . `Shipit::Api::CCMenuController`, however, overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` relation, bypassing the client's stack binding entirely [5](#0-4) . The permission check only verifies the generic `read:stack` permission string via `check_permissions!`, never that the requested `stack_id` matches `current_api_client.stack_id` [6](#0-5) .

### Finding Description
This is the "stack a token authorises versus a stack it touches" binding break described in the scan rules. A valid token issued for stack A (via `CCMenuUrlController`, or any other legitimately scoped API client with `read:stack`) authorizes read access to stack A's CI/build status only, per the `ApiClient#stack_id` binding. Because `CCMenuController#stack` reimplements stack resolution using the global `Stack` relation instead of the caller's scoped `stacks` helper, that same token can be replayed against `GET /api/stacks/*stack_id/ccmenu` with any other stack's `stack_id` path segment, and the controller will happily render that other stack's `deploys_and_rollbacks.last` build status, lock state, and activity in the XML response [7](#0-6) . The `authentication_token` itself carries no stack binding — it's a signed message containing only the `ApiClient` id [8](#0-7)  — so the only enforcement point for the per-stack restriction is the controller-level `stacks` scoping, which this controller skips.

### Impact Explanation
An attacker holding any `read:stack`-scoped `ApiClient` token (e.g., a CCMenu token generated for a single, low-sensitivity stack that a legitimate user shared or embedded in a CI dashboard) can use it to read the build/lock/activity status of every other stack in the Shipit instance, including ones they were never authorized to see. This is unauthorized cross-stack read of stack state, matching the "High" impact category (unauthenticated/unauthorized read of stack state).

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient`s (the CCMenu integration is a built-in, documented mechanism for exactly this — `CCMenuUrlController` and the settings UI expose a "CCMenu URL" containing the token). Any holder of one such URL/token can enumerate other stacks (stack ids are just `owner/repo/environment` paths, easily guessable/enumerable via the stacks index) and query their CCMenu status without further privilege.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` helper inherited from `BaseController` (i.e., remove the local override, or reimplement it as `stacks.from_param!(params[:stack_id])`) so that a stack-scoped `ApiClient` cannot query stacks outside its `stack_id` binding.

### Proof of Concept
1. As an authorized Shipit user, visit a stack's settings page and note/generate its CCMenu URL, which contains a token for an `ApiClient` scoped to `stack_id: A` with permission `read:stack` (via `CCMenuUrlController#client`) [4](#0-3) .
2. Send `GET /api/stacks/<other_owner>/<other_repo>/<other_env>/ccmenu?token=<that_token>` for a different stack B that the token was never authorized for.
3. Observe the response renders stack B's `deploys_and_rollbacks.last` status/lock/activity via `shipit/ccmenu/project` template [7](#0-6) , despite the token only being scoped (and only ever intended to authorize) stack A.

### Citations

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-25)
```ruby
      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
```

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

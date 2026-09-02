### Title
Stack-scoped API tokens can read CCMenu status for stacks outside their authorized scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` tokens can be scoped to a single stack via `stack_id`, and every other API controller enforces that scope by resolving the target stack through the client-scoped `stacks` collection. `Shipit::Api::CCMenuController` overrides the `stack` resolver to bypass that scoping, allowing a token that is authorized ("stack it authorizes") for one stack to read CCMenu status data for any stack in the instance ("stack it touches").

### Finding Description
`Shipit::Api::BaseController` defines the scoping contract used everywhere else in the API: [1](#0-0) 

`current_api_client.stack_id?` restricts the visible stack set to the one stack the token was created for; `stack` then resolves `params[:stack_id]` only within that restricted set. `Shipit::Api::StacksController` (and the other stack-scoped API controllers) rely on this inherited `stack` method, so a token scoped to stack A raises `ActiveRecord::RecordNotFound` if `params[:stack_id]` points at stack B.

`CCMenuController`, however, defines its own `stack` method that queries the unscoped `Stack` model directly: [2](#0-1) 

The only authorization check applied to this action is a permission-name check, not a stack-scope check: [3](#0-2) [4](#0-3) 

`check_permissions!` only verifies that `read:stack` is in the client's permission list; it never inspects `current_api_client.stack_id`. Because `CCMenuController#stack` doesn't route through `BaseController#stacks`, the `stack_id` scope binding — "the stack this token authorizes" — is never checked against "the stack this request actually touches."

**Binding broken:** `token.stack_id == requested_stack.id` (enforced everywhere else via `BaseController#stacks`) is **not** enforced in `CCMenuController#show`, which instead evaluates `Stack.from_param!(params[:stack_id])` unconditionally.

### Impact Explanation
An attacker who holds *any* legitimately-issued API token with the `read:stack` permission and a non-empty `stack_id` scope (e.g. a CCMenu-only token that an application intentionally minted for a single project, as done by `CCMenuUrlController`) can pass an arbitrary `stack_id` to `GET /api/stacks/:stack_id/ccmenu.xml` and read `name`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, and `webUrl` for any other stack in the Shipit instance, including private/internal stacks the token was never meant to see. This is an unauthorized read of stack state guarded by a scope binding that other controllers correctly enforce, matching the "High: unauthenticated/unauthorized read of stack state" impact class.

### Likelihood Explanation
High. Scoped, `read:stack`-only tokens are an intended, low-privilege token shape in this engine — `CCMenuUrlController#client` mints exactly such a token (`permissions: %w[read:stack]`, scoped to a specific stack) for embedding in third-party CI dashboards: [5](#0-4) 
Any holder of such a token (which is designed to be shared with external tooling, e.g. embedded in a CCMenu client URL) can trivially enumerate other `stack_id` values and exploit the missing scope check with a single unauthenticated-of-other-stacks HTTP GET — no additional privilege or race condition needed.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the inherited, scope-respecting `stacks` collection instead of the unscoped `Stack` model, e.g. `stacks.from_param!(params[:stack_id])`, so that `current_api_client.stack_id` scoping is honored the same way it is in every other API controller.

### Proof of Concept
1. As an admin, create two stacks, `stack-a` and `stack-b`.
2. Mint (or have `CCMenuUrlController#fetch` mint) an `ApiClient` token scoped to `stack-a` only: `permissions: ['read:stack']`, `stack_id: stack_a.id`.
3. Using that token's `authentication_token` as Basic Auth credentials, request:
   `GET /api/stacks/stack-b-owner/stack-b-name/ccmenu.xml`
4. Observe HTTP 200 with `stack-b`'s CCMenu XML (`name`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`), even though the token is scoped to `stack-a` and would receive `404`/no-access if the same `stack_id` were requested through `Shipit::Api::StacksController#show`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
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

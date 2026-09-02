### Title
Stack-scoped ApiClient tokens bypass their `stack_id` restriction on the CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method used by `BaseController` in a way that drops the stack-scoping enforcement normally applied to `ApiClient` tokens. A token that an administrator deliberately restricted to a single stack (`ApiClient#stack_id`) can be replayed against the CCMenu endpoint to read the deploy status of *any* stack in the installation, breaking the "stack a token authorises versus a stack it touches" binding.

### Finding Description
`ApiClient` supports being scoped to a single stack via the `stack_id` column, and `BaseController` enforces that scope through its `stacks`/`stack` helpers: [1](#0-0) 

`stacks` restricts the visible set of stacks to `current_api_client.stack_id` when the client is scoped, and `stack` resolves the requested stack from that restricted collection (`stacks.from_param!`). This is the mechanism the fixture `here_come_the_walrus` (`stack: shipit`) exists to exercise, and the test "an api client scoped to a stack will only see that one stack" confirms it is a deliberate authorization boundary.

`CCMenuController`, however, redefines `stack` to load directly by parameter, completely bypassing the scoped `stacks` collection: [2](#0-1) 

It also allows authenticating via a `token` query-string parameter rather than only the `Authorization` header: [3](#0-2) 

Because `require_permission :read, :stack` only checks the permission string via `ApiClient#check_permissions!` and never checks `stack_id` binding: [4](#0-3) 

any valid `read:stack`-permitted token — including one an admin scoped to exactly one stack — can be used with a different `stack_id` in the URL (`/api/stacks/:stack_id/ccmenu.xml?token=...`) and will successfully resolve and render that other stack's CCMenu status, because `stack` in this controller never consults `current_api_client.stack_id`.

This mirrors the reported bug class: a security-relevant value (`stack_id` authorization scope) is checked in one code path (`BaseController#stack`) but the value actually acted upon (`Stack.from_param!(params[:stack_id])` in `CCMenuController#stack`) is taken unconditionally, so the binding "stack authorized == stack touched" is broken.

### Impact Explanation
An attacker who obtains (or is given) a stack-scoped read-only token — e.g. via the built-in `CCMenuUrlController#fetch` flow which mints `read:stack` tokens, or any admin-issued scoped `ApiClient` — can use that single token to read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, activity, lock reason, etc.) of every stack in the Shipit instance, not just the one it was authorized for. This is an unauthorized read of stack state across stacks the token holder should not have visibility into, matching the "High - unauthenticated/unauthorized read of stack state" impact category.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens (a supported, tested feature) and exposes the CCMenu endpoint, since exploitation requires only a valid token with `read:stack` permission and knowledge of another stack's identifier/slug — no additional privilege, signature, or repository access is needed.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` collection (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `stack_id` binding enforced elsewhere in `BaseController` also applies to the CCMenu endpoint.

### Proof of Concept
1. As an admin, create (or use `CCMenuUrlController#fetch` to create) an `ApiClient` scoped to `stack_id: <stack A id>` with `permissions: ['read:stack']`, and note its `authentication_token`.
2. Request `GET /stacks/<stack-B-owner>/<stack-B-repo>/<stack-B-env>/ccmenu.xml?token=<token-for-stack-A>` (any other stack the token was never authorized for).
3. Observe the request succeeds (`200 OK`) and returns stack B's CCMenu project status, despite the token being scoped only to stack A.

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

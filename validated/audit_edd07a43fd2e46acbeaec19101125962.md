### Title
Stack-scoped ApiClient token can read the status of any stack via CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` resolver used by `Shipit::Api::BaseController` in a way that removes the stack-scoping enforced for every other API endpoint. This breaks the binding "the stack an `ApiClient` token authorises == the stack it can touch," allowing an `ApiClient` token that was only ever authorised for one stack to read CI/build status data for any stack in the installation.

### Finding Description
`Shipit::Api::BaseController` restricts the resolvable stacks to the ones the authenticated `ApiClient` is allowed to see: [1](#0-0) 
`stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client has a `stack_id`, otherwise `Stack.all`, and `stack` resolves `params[:stack_id]` only within that scoped relation.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 
It calls `Stack.from_param!(params[:stack_id])` directly against the full `Stack` table, ignoring `current_api_client.stack_id`. The controller only checks a coarse `read:stack` permission bit via `require_permission :read, :stack`: [3](#0-2) 
`ApiClient#check_permissions!` only verifies the client has the `read:stack` permission string in its `permissions` list — it never checks which stack the client is bound to: [4](#0-3) 

So any `ApiClient` record with `read:stack` permission — including ones deliberately scoped to a single stack via `belongs_to :stack, optional: true` — can be used to fetch CCMenu status (`lastBuildStatus`, `lastBuildLabel`, lock state, etc.) for every stack in the Shipit instance, not just the one it was created for. `CCMenuUrlController` further demonstrates that a scoped client can be minted for a single stack's CCMenu display and is expected to be limited to it: [5](#0-4) 

Equality broken: `token.stack_id == stack_shown_to_holder` before the change; after using the endpoint, `token.stack_id != params[:stack_id]` is permitted because `CCMenuController#stack` never consults `current_api_client.stack_id`.

### Impact Explanation
This is an authorization escalation across the stack boundary: possession of a narrowly-scoped, low-privilege token (issued/expected to expose only one stack's CI status, e.g. via `CCMenuUrlController`) is sufficient to read deploy/build state — including lock status and last build label — of every other stack managed by the Shipit instance. This matches the "stack a token authorises versus a stack it touches" binding explicitly called out as in-scope, and constitutes unauthorized cross-stack read access to stack state.

### Likelihood Explanation
Any holder of a valid `ApiClient` token with the `read:stack` permission (including the intentionally stack-scoped ones minted by `CCMenuUrlController`, which are handed out to be embedded in third-party CI dashboard tools) can trivially exploit this by changing the `stack_id` request parameter — no special conditions or races required.

### Recommendation
Change `CCMenuController#stack` to resolve through the same scoped `stacks` relation used elsewhere (e.g., `stacks.from_param!(params[:stack_id])`) so the `current_api_client.stack_id` restriction is enforced consistently, matching `BaseController#stack`.

### Proof of Concept
1. As a user, create a stack-scoped CCMenu token for `stack-A` via `CCMenuUrlController#fetch` (`GET /:stack_id/ccmenu_url`), which creates/fetches an `ApiClient` with `permissions: ['read:stack']` intended for `stack-A`.
2. Using that token, call:
   `GET /api/stacks/:other_stack_id/ccmenu.xml?token=<token>` where `:other_stack_id` is any other stack the token holder was never granted access to.
3. Observe the request succeeds (`assert_response :ok` per the existing test pattern in `test/controllers/api/ccmenu_controller_test.rb`), returning the CI/build status of the unauthorized stack, because `CCMenuController#stack` (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`) never applies the `current_api_client.stack_id` scoping present in `BaseController#stacks`/`#stack`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

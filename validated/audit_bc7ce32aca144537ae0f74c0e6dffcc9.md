### Title
`CCMenuController#stack` bypasses stack-scoped `ApiClient` authorization, letting a stack-scoped token read any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true`, exposed as `stack_id?`. `Api::BaseController` enforces this binding centrally through its `stacks`/`stack` helper methods, but `Api::CCMenuController` reimplements `#stack` using the unscoped `Stack.from_param!` instead of the scoped `stacks.from_param!`, breaking the "stack the token authorizes == stack it touches" equality.

### Finding Description
`Api::BaseController` establishes the trust binding between an `ApiClient` and the stack(s) it may act on: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?` true), and `stack` resolves `params[:stack_id]` against that restricted set. Every other API controller (e.g. `StacksController`) relies on this same `stack`/`stacks` helper, so a token created with `stack: shipit` (see fixture `here_come_the_walrus`) can only ever resolve stacks belonging to that one record: [2](#0-1) 

`CCMenuController`, however, overrides `#stack` to bypass this scope entirely: [3](#0-2) 

It calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model rather than through the `stacks` scope inherited from `BaseController`. The `require_permission :read, :stack` before_action only checks `ApiClient#check_permissions!`, which verifies the token has the `read:stack` permission string — it performs no per-stack comparison: [4](#0-3) 

So the only enforcement of "this token may only touch stack X" lives in the `stacks` scoping method, and `CCMenuController` is the one endpoint in the API surface that omits it.

The equality binding that should hold is:
`current_api_client.stack_id? ? (stack requested == current_api_client.stack_id) : true`

`CCMenuController#stack` instead evaluates unconditionally to `Stack.from_param!(params[:stack_id])`, i.e. always `true` regardless of `current_api_client.stack_id`, breaking the binding whenever the client is stack-scoped.

### Impact Explanation
Any holder of a valid, stack-scoped `ApiClient` token with `read:stack` permission (e.g. an unprivileged integration such as a CI status badge or CCMenu client explicitly created with `permissions: %w[read:stack]` and bound to one stack — see `CCMenuUrlController#client`, which programmatically mints such scoped tokens) can query `GET /api/stacks/:stack_id/cc_menu.xml` for *any other stack ID* in the installation, not just the one it was issued for. This discloses another team/repository's build/deploy status (last build result, lock state, activity) — an unauthorized cross-stack read of stack state, matching the "High: unauthenticated/unauthorized read of stack state ... task streams or deploy output" impact category, since the token that was authorized for stack A is used to read stack B, a boundary the application otherwise strictly enforces everywhere else in the API. [5](#0-4) 

### Likelihood Explanation
Any party in possession of a scoped CCMenu-style read token (these are routinely distributed to CI dashboards, and `CCMenuUrlController` mints them via a simple `find_or_create_by!`) can trivially trigger this by substituting a different `stack_id` in the request path. No special privilege beyond holding one legitimate scoped token is required, and the flaw is a straightforward code-path divergence (missed use of the shared `stacks` scope) rather than requiring any race condition or edge case.

### Recommendation
Change `Api::CCMenuController#stack` to reuse the inherited scoped lookup instead of querying `Stack` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the same `current_api_client.stack_id? → Stack.where(id: current_api_client.stack_id)` binding used by every other API endpoint, ensuring a stack-scoped token can only ever resolve the stack it was issued for.

### Proof of Concept
1. Create (or use `CCMenuUrlController#client`) an `ApiClient` scoped to `stack: A` with `permissions: ['read:stack']`, and obtain its `authentication_token`.
2. As that client, issue:
   `GET /api/stacks/:B_id/cc_menu.xml?token=<token-scoped-to-A>` where `B` is a different stack the token was never granted.
3. `authenticate_api_client` succeeds (token is valid), `require_permission :read, :stack` passes (`check_permissions!` only checks the string `read:stack`, not which stack), and `stack` resolves `Stack.from_param!(B)` unconditionally — returning stack B's build status even though the token's `stack_id` is `A`.
4. Compare with any other API endpoint, e.g. `Api::StacksController#show` calling `stack` → `stacks.from_param!(params[:id])`: the same token requesting stack B there correctly raises `ActiveRecord::RecordNotFound` (scoped to `Stack.where(id: A)`), confirming `CCMenuController` is the outlier that breaks the binding.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

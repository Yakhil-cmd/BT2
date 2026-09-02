Confirmed: `app/controllers/shipit/api/ccmenu_controller.rb` overrides `stack` to use `Stack.from_param!(params[:stack_id])` directly, bypassing `BaseController#stacks` scoping (`current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`). This breaks the exact binding class described in the rules ("a stack a token authorises versus a stack it touches"), and the fixture `here_come_the_walrus` demonstrates an `ApiClient` scoped to a single stack that would be expected to only access that stack.### Title
API token scoped to one stack can read CCMenu build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces that an `ApiClient` scoped to a specific `stack_id` can only resolve stacks through the `stacks` scope: `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) . `Shipit::Api::CCMenuController` overrides the `stack` accessor with `Stack.from_param!(params[:stack_id])`, completely bypassing that scoping check [2](#0-1) .

### Finding Description
The binding being broken is: *the stack a token authorises* (`ApiClient#stack_id`, checked via `BaseController#stacks`) versus *the stack the request actually touches* (`CCMenuController#stack`).

- `ApiClient` supports being scoped to a single `stack` (`belongs_to :stack, optional: true`) [3](#0-2) , and the fixture `here_come_the_walrus` is exactly this kind of token, scoped to the `shipit` stack with only `read:stack` permission [4](#0-3) .
- The intended enforcement mechanism for this scoping lives in `BaseController#stacks`/`#stack`, used by every other API controller that relies on the inherited `stack` method (e.g. `Api::StacksController`, `Api::MergeRequestsController`) [1](#0-0) .
- `Api::CCMenuController` re-defines `stack` to call `Stack.from_param!(params[:stack_id])` directly instead of delegating through `stacks` [5](#0-4) . `require_permission :read, :stack` only checks that the string `"read:stack"` exists in `current_api_client.permissions` [6](#0-5)  — it performs no per-stack authorization at all. Because the `stack` scope check is the *only* place stack-level authorization is enforced, and `CCMenuController` skips it, any `ApiClient` with `read:stack` permission — even one scoped to a single stack — can pull `deploys_and_rollbacks` state (last deploy status, lock state, sha, etc.) for **every** stack in the installation by simply passing a different `stack_id` param, just like the guard/module binding in the original report was checked at one layer (`Safe.execTransaction`'s guard check) but bypassed at another layer (`execTransactionFromModule`).

### Impact Explanation
This is an authenticated but unauthorized cross-stack read: a token issued/authorized for stack A (e.g. via `CCMenuUrlController#client`, which mints a `read:stack`-only, stack-scoped `ApiClient` embedded in a shareable CCTray URL [7](#0-6) ) can be used to read build/deploy status, lock reason, and last build metadata for any other stack in the Shipit instance, including stacks it was never meant to access. This matches the "unauthenticated/unauthorized read of stack state" high-severity impact class: the token holder gains visibility into deploy state of repositories/environments outside its authorized scope.

### Likelihood Explanation
Trivial to exploit: the attacker only needs any valid `ApiClient` token with `read:stack` permission (including a narrowly-scoped, low-privilege token such as the `CCMenuUrlController`-issued token meant to be shared semi-publicly for CI status badges) and can simply substitute an arbitrary `stack_id` in the URL. No additional privileges, signatures, or GitHub access are required.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` method inherited from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so that stack-scoped `ApiClient` tokens are restricted to their authorized stack, consistent with every other API controller.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack: shipit` with permission `read:stack` (as in fixture `here_come_the_walrus`, or via `CCMenuUrlController#fetch`).
2. Authenticate to `GET /api/stacks/:other_stack_id/ccmenu` (routed to `Api::CCMenuController#show`) using that token, passing a `stack_id` for a stack the token was never scoped to.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly rather than `stacks.from_param!(...)`, the request succeeds and returns build/deploy status for the unauthorized stack, even though `BaseController#stacks` would have restricted `Stack.where(id: current_api_client.stack_id)` for this exact token in every other controller.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/api_client.rb (L4-9)
```ruby
  class ApiClient < Record
    InsufficientPermission = Class.new(StandardError)

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

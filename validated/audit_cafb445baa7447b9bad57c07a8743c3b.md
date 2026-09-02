### Title
Stack-scoped API tokens can read build status of any stack via CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the shared `stack` lookup helper with a version that resolves the target stack directly from `Stack.from_param!`, bypassing the `ApiClient` stack-scoping enforced everywhere else in the API. A token created with `stack_id` set (i.e. an `ApiClient` meant to be restricted to a single stack) can be replayed against any other stack's CCMenu endpoint to read that stack's build status.

### Finding Description
`Shipit::ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true` [1](#0-0) , as demonstrated by the `here_come_the_walrus` fixture which sets `stack: shipit` and only `read:stack` permission [2](#0-1) .

Every other API controller resolves the requested stack through `Shipit::Api::BaseController#stack`, which is derived from the scoped `stacks` collection:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [3](#0-2) 

This ensures a token scoped to one stack (`stack_id` present) can only ever resolve that stack, regardless of what `params[:stack_id]` says.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

The only permission check performed is `require_permission :read, :stack` [5](#0-4) , which resolves to `ApiClient#check_permissions!` — a pure string-membership check against the `permissions` array, with no awareness of `stack_id` at all:
```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
``` [6](#0-5) 

The binding that is broken is: **the stack a token authorizes (`ApiClient#stack_id`) vs. the stack it actually touches (`params[:stack_id]` resolved unscoped by `CCMenuController#stack`)**. Before the attacker's request, holding a token with `stack_id = A` should equal "can only read stack A". After hitting `GET /api/:B/ccmenu.xml?token=<tokenA>`, the attacker reads stack B's data instead.

### Impact Explanation
This allows unauthenticated (relative to the target stack) read access to any stack's build/deploy status (activity, last build status/label/time, web URL) using a token that was only ever authorized for a different, single stack. This matches the "unauthenticated read of stack state" High-impact category, since the scoping guarantee that stack-restricted tokens are supposed to provide is silently defeated for this one endpoint.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (e.g. a CI dashboard integration or third party given a narrowly-scoped `read:stack` token for their own stack) can trivially exploit this by substituting a different `stack_id` in the URL — no additional privilege or race condition is required, only knowledge of another stack's identifier.

### Recommendation
Remove the `stack` override in `CCMenuController`, or make it call the scoped `stacks` collection (`stacks.from_param!(params[:stack_id])`) exactly like `BaseController#stack`, so stack-scoped tokens cannot resolve stacks outside their `stack_id`.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to stack `A` with only `read:stack` permission (e.g. via the `here_come_the_walrus` pattern), and note its `authentication_token`.
2. As this token's holder, issue: `GET /api/<owner>/<repo-B>/<env-B>/ccmenu.xml?token=<tokenA>` where `B` is a stack the token was never scoped to.
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly instead of the scoped `stacks` collection, the request succeeds and returns stack `B`'s CCMenu XML (build status, activity, etc.), even though the token is restricted to stack `A` everywhere else in the API.

### Citations

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end
```

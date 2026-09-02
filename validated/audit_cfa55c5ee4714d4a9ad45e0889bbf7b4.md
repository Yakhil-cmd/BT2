### Title
Stack-scoped API token can read CCMenu status of any stack, bypassing its authorized scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack with `Stack.from_param!(params[:stack_id])`, bypassing the scope enforcement that every other API controller relies on through `Shipit::Api::BaseController#stacks`/`#stack`. An `ApiClient` that is restricted to a single stack via `stack_id` can therefore use its token to read the CCMenu XML status (build status, lock status, last deploy time) of any other stack in the installation, not just the one it was scoped to.

### Finding Description
`Shipit::Api::BaseController` defines the intended authorization binding between a token and the stacks it may touch: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Every controller that inherits `#stack` from `BaseController` (e.g. `Api::CommitsController`, `Api::TasksController`) is implicitly scoped by `current_api_client.stack_id`. However, `Api::CCMenuController` overrides `#stack` and calls `Stack.from_param!` directly on the unscoped `Stack` relation: [2](#0-1) 

This breaks the equality that should hold: `current_api_client.stack_id` (the stack the token authorizes) == the stack resolved from `params[:stack_id]` (the stack actually touched by `#show`). The `require_permission :read, :stack` declaration on this controller only checks that the client's `permissions` array contains `"read:stack"` (`ApiClient#check_permissions!`, [3](#0-2) ); it never checks that `params[:stack_id]` matches `current_api_client.stack_id`. That check only happens implicitly through `BaseController#stacks`, which `CCMenuController` does not use.

### Impact Explanation
An operator can legitimately create a scoped `ApiClient` (e.g. `here_come_the_walrus` fixture: [4](#0-3) ) intended to expose CI/CCMenu status for only one stack to an external system (e.g. a status dashboard, CI tool). Because `CCMenuController#stack` ignores the scope, that same token can be used to read deploy/lock/build status of every other stack managed by the Shipit instance, an unauthorized cross-stack read of stack state. This matches the High-impact category of "unauthenticated/unauthorized read of stack state" via a scope bypass on an authenticated token.

### Likelihood Explanation
This requires no privileged access beyond possessing a normally-issued, narrowly-scoped `ApiClient` token — which is exactly the kind of low-trust credential this scoping mechanism exists to protect against. Any holder of a single-stack scoped token can trivially trigger the bypass by supplying a different `stack_id` in the request URL/params, since `Stack.from_param!` performs no ownership check. This is a straightforward, deterministic bypass, not a race condition or timing issue.

### Recommendation
Change `CCMenuController#stack` to resolve through the scoped `stacks` relation, consistent with `BaseController`:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
and remove the private override entirely so it inherits the scoped behavior from `BaseController`.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to `Stack A` (`stack_id` set) with `permissions: ["read:stack"]`.
2. Note its `authentication_token`.
3. Send: `GET /ccmenu/<stack_B_to_param>.xml?token=<token>` (or via HTTP Basic auth), where `Stack B` is a different, unauthorized stack.
4. Observe `200 OK` with `Stack B`'s CCMenu XML (name, lastBuildStatus, lastBuildLabel, lastBuildTime, webUrl) returned, even though the token is only supposed to be authorized for `Stack A`. Compare with the same token used against `Api::CommitsController#index` for `Stack B`, which correctly returns `404`/empty because `BaseController#stacks` scopes it out — demonstrating the discrepancy is specific to `CCMenuController`.

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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

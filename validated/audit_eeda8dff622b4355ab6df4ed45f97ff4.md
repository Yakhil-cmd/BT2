### Title
Stack-scoped `ApiClient` token bypasses stack authorization in `Api::CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
The retryMessage report's root cause is a state re-validation gap: a privilege/authorization check (RETRIABLE) is enforced once, but the subsequent action is executed against inputs (`_addr`, `msgHash`) that are never re-checked against the authorization state that should still bind it. The equivalent binding in this Rails engine is: *a stack a token authorizes* versus *a stack it touches*. `Api::CCMenuController` breaks exactly this binding by resolving the target `Stack` without applying the `ApiClient`'s stack scope.

### Finding Description
`Shipit::Api::BaseController` establishes the authorization binding between an `ApiClient` and the stacks it may act on: [1](#0-0) 

`stacks` restricts the queryable set to `current_api_client.stack_id` when the client is scoped to a single stack, and `stack` resolves the `:stack_id` param *through* that scoped relation (`stacks.from_param!`), so a lookup for a stack outside the client's scope raises `ActiveRecord::RecordNotFound`.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It resolves `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table instead of `stacks.from_param!`, and `require_permission :read, :stack` only checks the coarse-grained permission string `read:stack` on the `ApiClient` model (`ApiClient#check_permissions!`) — it never checks the resolved stack against `current_api_client.stack_id`: [3](#0-2) 

The `#show` action then serves `stack.deploys_and_rollbacks.last`, i.e., the actual deploy/rollback state of whatever stack ID the requester supplies: [4](#0-3) 

Before the attacker's request: an `ApiClient` scoped to `stack_id: A` (e.g. fixture `here_come_the_walrus`, permissions `['read:stack']`) can only see stack `A` via every other API endpoint (`BaseController#stacks`/`#stack`), matching the equality *token.stack == queried.stack*.
After a request to `GET /api/stacks/:stack_id/ccmenu.xml?token=<A's token>` with `:stack_id` set to an unrelated stack `B`: the equality is violated — *token authorizes A* but *action touches B* — because `CCMenuController#stack` never intersects the lookup with `current_api_client.stack_id`.

### Impact Explanation
This is an authorization-scope escalation: a token deliberately restricted (by an admin, via `ApiClient#stack_id`) to a single stack can read the deploy/rollback status, last build label (commit sha), last build time, activity, and web URL of any other stack in the Shipit instance, matching the report's "High — unauthenticated read of stack state, task streams or deploy output" category, since the disclosure occurs entirely outside the token's granted authorization boundary.

### Likelihood Explanation
Any holder of a stack-scoped `ApiClient` token (a low-privilege credential intentionally restricted to one stack, e.g. distributed to a CI dashboard or CCMenu client per stack) can trivially trigger this by changing the `:stack_id` route/query parameter — no additional access or secret is required beyond the token they already legitimately hold for a different, single stack.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the scoped `stacks` relation exactly as `BaseController#stack` does (`stacks.from_param!(params[:stack_id])`), so the `current_api_client.stack_id` restriction is enforced consistently across all API controllers, including CCMenu.

### Proof of Concept
1. Create/observe an `ApiClient` scoped to stack `A` (`stack_id` set) with permission `read:stack` (mirrors fixture `here_come_the_walrus` in `test/fixtures/shipit/api_clients.yml`). [5](#0-4) 
2. Note that other endpoints correctly restrict this token: `test/controllers/api/stacks_controller_test.rb` shows `authenticate!(:here_come_the_walrus)` limited to a single stack when listing. [6](#0-5) 
3. Using that same token as the `?token=` query parameter, request `GET /api/stacks/<B>/ccmenu.xml` where `B` is a *different* stack than the one the token is scoped to.
4. `CCMenuController#stack` resolves `B` via unscoped `Stack.from_param!`, and `#show` renders `B`'s real deploy status, bypassing the stack scoping enforced everywhere else in the API. [7](#0-6)

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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```

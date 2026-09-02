The bug-class here — a value acted upon (the actual stack fetched) diverging from the value that was supposed to gate/authorize the action (the stack a scoped API token is bound to) — maps directly onto a real binding break in `Api::CCMenuController`.

### Title
Stack-scoped `ApiClient` tokens can read the CI/deploy status of any stack via the CCMenu endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via `stack_id`. Every other API controller honors this by resolving the target stack through `BaseController#stacks`, which restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the token is scoped. `Api::CCMenuController` overrides `#stack` to bypass this scoping entirely, breaking the equality "stack a token authorizes == stack it touches".

### Finding Description
`BaseController#stacks` is the intended authorization boundary for scoped tokens: [1](#0-0) 

Regular resource controllers derive `stack` from this scoped collection, e.g. `Api::StacksController` and `Api::TasksController` implicitly rely on `stacks.from_param!(params[:stack_id])` inherited from `BaseController`.

`Api::CCMenuController`, however, defines its own `stack` method that queries the global `Stack` relation directly, ignoring the api client's `stack_id` scope entirely: [2](#0-1) 

The only gate on the action is `require_permission :read, :stack`, which checks the permission *name* (`read:stack`) on the token, not which stack it is scoped to: [3](#0-2) 

So the equality that should hold — `authorized_stack(token) == stack_touched_by(request)` — is broken: any token with the `read:stack` permission, even one created with `stack_id` set specifically to limit it to one stack (see fixture `here_come_the_walrus`, scoped to the `shipit` stack), can pass an arbitrary `stack_id` param and read CI/deploy status (`deploys_and_rollbacks`) for a completely different stack it was never authorized to see. [4](#0-3) 

For comparison, `Api::StacksControllerTest` confirms the intended enforcement exists and is expected elsewhere in the API surface: [5](#0-4) 

### Impact Explanation
This is an unauthorized read of stack state/deploy output using a token that was deliberately restricted to a single stack — falling under the accepted High-impact category of "unauthorized read of stack state, task streams or deploy output" that escalates beyond the authorization granted to the token.

### Likelihood Explanation
High. No special privileges are needed beyond possessing any valid, stack-scoped API token with `read:stack` permission (a common, low-privilege credential intentionally created to be narrowly scoped, e.g. via `CCMenuUrlController`/`ApiClient.create_with(permissions: %w[read:stack])`). The attacker only needs to change the `stack_id` route/query parameter.

### Recommendation
Make `Api::CCMenuController#stack` use the same scoped lookup as the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the direct `Stack.from_param!` bypass so that stack-scoped tokens cannot touch stacks outside their authorized scope.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to stack A only (`stack_id` set, permissions include `read:stack`), e.g. fixture `here_come_the_walrus` scoped to the `shipit` stack.
2. As that client, issue `GET /api/stacks/:stack_id_of_stack_B/ccmenu.xml?token=<here_come_the_walrus_token>` where stack B is unrelated to the token's `stack_id`.
3. `authenticate_api_client` in `CCMenuController` succeeds because `ApiClient.authenticate(params[:token])` only validates the signature, not the stack.
4. `require_permission :read, :stack` passes because the token has the `read:stack` permission (permission name only).
5. `stack` resolves stack B directly via `Stack.from_param!`, bypassing the `stacks` scoping that would have returned `Stack.none` for stack B.
6. The response renders stack B's build/deploy status (`name`, `activity`, `lastBuildStatus`, etc.), which the token was never authorized to view.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
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

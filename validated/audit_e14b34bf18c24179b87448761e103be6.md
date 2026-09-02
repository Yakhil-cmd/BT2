### Title
Stack-scoped ApiClient tokens can read any stack's build status via CCMenuController, bypassing stack authorization scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`CCMenuController#stack` resolves the target stack with `Stack.from_param!(params[:stack_id])` [1](#0-0)  instead of using the tenant-scoped `stacks`/`stack` helpers defined in `BaseController`, which restrict a stack-scoped `ApiClient` to only the stack referenced by its `stack_id` column [2](#0-1) . This breaks the binding "the stack a token authorizes == the stack it touches": a CI-badge token issued for stack A can be replayed against `stack_id` of stack B and still pass the permission check.

### Finding Description
`ApiClient` tokens can be scoped to a single stack via the `stack_id` column, and `BaseController` enforces this by computing `stacks` as `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`, then resolving the requested stack via `stacks.from_param!(params[:stack_id])` [2](#0-1) . This is the mechanism that keeps a "read:stack" badge/CI token from reading stacks it was not issued for.

`CCMenuController`, used to expose CI status ("CCMenu"/CCTray-style badge feed) is designed to be embedded in public places (READMEs, dashboards) and therefore even overrides `authenticate_api_client` to accept the token from a URL query parameter instead of Basic Auth [3](#0-2) . Critically, it also overrides the private `stack` method to look the stack up unscoped:

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 

`require_permission :read, :stack` only checks that the token has the `read:stack` permission string in its permission list (`ApiClient#check_permissions!`) [5](#0-4)  — it never re-checks that `params[:stack_id]` matches `current_api_client.stack_id`. Because `stack` bypasses the `stacks` scoping helper entirely, any token with `read:stack` permission (including one whose `stack_id` column restricts it to a single stack) can be pointed at an arbitrary `stack_id` in the URL and will successfully render that other stack's latest deploy/rollback status via `show` [6](#0-5) .

Binding broken (as an equality):
`stack authorized by token.stack_id` == `stack actually read by CCMenuController#show` — this holds everywhere else in the API (`BaseController#stack`) but is violated in `CCMenuController`.

### Impact Explanation
This matches the "High" impact category "unauthenticated read of stack state, task streams or deploy output": a token deliberately restricted to a single stack (e.g., a badge URL published in a public README, which is the intended low-trust use case for CCMenu tokens) can be used to read the deploy/rollback status — including stack names, deploy outcomes, and timing — of any other stack in the Shipit instance, not just the one it was scoped to.

### Likelihood Explanation
Any holder of a stack-scoped `read:stack` ApiClient token (a credential explicitly designed for low-trust/public embedding, e.g. CI badges) can trivially trigger this by changing the `stack_id` route/query parameter. No privileged account, GitHub credentials, or webhook secret are required — only possession of a token that was intentionally scoped to a single stack.

### Recommendation
In `CCMenuController#stack`, reuse the tenant-scoped `stacks` helper from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so that a stack-scoped `ApiClient` cannot resolve stacks outside `current_api_client.stack_id`.

### Proof of Concept
1. Admin creates a stack-scoped `ApiClient` with `stack_id` set to Stack A and permission `read:stack`, intended to be embedded as a public CI badge URL for Stack A only.
2. Attacker takes that published token/URL and requests `GET /api_clients_token/ccmenu.xml?stack_id=<Stack B id>` (or equivalent route parameter for Stack B).
3. `authenticate_api_client` succeeds using the query-param token [3](#0-2) ; `require_permission :read, :stack` passes because the token has `read:stack` [5](#0-4) ; `stack` resolves Stack B unscoped [4](#0-3) .
4. The response renders Stack B's latest deploy/rollback status, which the token was never authorized to view.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
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

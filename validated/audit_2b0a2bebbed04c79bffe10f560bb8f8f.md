## Title
CCMenuController bypasses per-stack ApiClient authorization scoping, allowing stack-scoped tokens to read status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::BaseController` enforces two independent authorization layers for API clients: (1) an operation/scope permission string (e.g. `read:stack`), checked via `require_permission!`, and (2) a stack-ownership scope, enforced by routing all stack lookups through the `stacks` helper, which restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is bound to a specific stack. `CCMenuController` re-implements its own `stack` accessor that calls `Stack.from_param!(params[:stack_id])` directly, completely bypassing the `stacks` scoping helper, so the stack-ownership binding is never checked for this endpoint.

### Finding Description
`Shipit::Api::BaseController` defines the scoping binding as: [1](#0-0) 

This means: **the set of stacks an `ApiClient` token authorizes == `Stack.where(id: current_api_client.stack_id)` when `stack_id` is set**, and every controller that inherits `stack` from `BaseController` (e.g. `DeploysController`) benefits from this restriction, as also validated by the test "an api client scoped to a stack will only see that one stack" for `StacksController#index`.

`CCMenuController`, however, overrides `stack` to look up the record independently of the client's scope: [2](#0-1) 

`require_permission :read, :stack` only calls `current_api_client.check_permissions!('read', 'stack')`, which merely checks that the permission string `"read:stack"` is present in the client's `permissions` array: [3](#0-2) 

It never checks `current_api_client.stack_id` against the requested `stack_id`. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` instead of the scoped `stacks.from_param!(params[:stack_id])` used by `BaseController#stack`, **any** `ApiClient` holding the `read:stack` permission — even one explicitly scoped to a single stack via `ApiClient#stack_id` (e.g. fixture `here_come_the_walrus`, which is scoped to the `shipit` stack and used elsewhere to prove per-stack scoping) — can supply an arbitrary `stack_id` param and read that stack's CCMenu status.

Before the missing check: the binding "stack a token authorizes" == "stack a token touches" holds only in `BaseController`/`DeploysController`/`StacksController`, but is broken specifically in `CCMenuController`. After: `CCMenuController` looks up any stack in the system regardless of the requesting client's `stack_id` binding.

### Impact Explanation
The CCMenu endpoint discloses stack state: `name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, and whether a stack is locked, as shown by the response fields asserted in the controller test: [4](#0-3) 

An attacker holding a legitimately-issued, narrowly-scoped API token (scoped to one stack, with only `read:stack` permission) can enumerate and read the deploy/build status of every other stack in the Shipit instance, including stacks they were never granted access to. This matches the "High - unauthenticated read of stack state" category defined by the rules, since the token holder is unauthorized/unauthenticated with respect to the other stacks it can now read.

### Likelihood Explanation
Likelihood is high for anyone already possessing a valid, stack-scoped `ApiClient` token (a normal, intended use case for CI systems using CCMenu/CCTray integrations) — no additional privilege is required, only supplying a different `stack_id` query parameter. This requires only an `ApiClient` token, which is a documented/expected credential for this endpoint, not a privileged one.

### Recommendation
Change `CCMenuController#stack` to reuse the inherited scoped lookup, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
or simply remove the override entirely so `BaseController#stack` (which uses `stacks.from_param!`) is used, ensuring the `current_api_client.stack_id` binding is enforced consistently with the rest of the API controllers.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_a` (`stack_id = stack_a.id`) with `permissions: ['read:stack']` (analogous to fixture `here_come_the_walrus`).
2. Using that client's `authentication_token`, issue: `GET /api/1.0/stacks/other_org/other_repo/production/cc.xml?token=<token>` (i.e., `stack_id` pointing to `stack_b`, a stack the client is not scoped to).
3. `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `stacks`), so `stack_b`'s CCMenu XML (name, lastBuildStatus, lastBuildLabel, lastBuildTime, webUrl, activity) is returned with `200 OK`, despite the client only being authorized for `stack_a`.

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

**File:** test/controllers/api/ccmenu_controller_test.rb (L33-45)
```ruby
      test "xml contains required attributes" do
        get :show, params: { stack_id: @stack.to_param }
        project = get_project_from_xml(response.body)
        %w[name activity lastBuildStatus lastBuildLabel lastBuildTime webUrl].each do |attribute|
          assert_includes project, attribute, "Response missing required attribute: #{attribute}"
        end
      end

      test "locked stacks show as failed" do
        @stack.lock('test', @user)
        get :show, params: { stack_id: @stack.to_param }
        assert_payload 'lastBuildStatus', 'Failure'
      end
```

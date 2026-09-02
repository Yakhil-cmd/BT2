### Title
CCMenu API endpoint bypasses per-client stack scoping, letting a stack-scoped API token read the CI/deploy status of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
### Finding Description
The underlying bug class in the external report is a mismatch between the value a caller is entitled to (the requested `assets`) and the value actually acted upon by the privileged operation (the transferred `value`), because the code path that resolves the final value bypasses the check that was supposed to bind the two together. The same class of bug exists in this engine's API authorization layer: `Shipit::Api::BaseController` establishes the binding "an `ApiClient` token authorizes only the `Stack` it is scoped to" via the `stacks` helper: [1](#0-0) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

Every other API controller (`DeploysController`, `StacksController`, etc.) resolves `stack` through this scoped helper, so a client created with a `stack_id` (i.e. `here_come_the_walrus` in the fixtures) can only reach the one `Stack` it was scoped to.

`Shipit::Api::CCMenuController`, however, overrides both the authentication method and the `stack` resolver, and in doing so drops the scoping entirely: [2](#0-1) 

```ruby
class CCMenuController < BaseController
  require_permission :read, :stack
  ...
  def show
    latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
    render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
  end

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

`stack` here calls `Stack.from_param!` directly on the whole `Stack` model, not on the `stacks` (client-scoped) relation defined in the base controller. `require_permission :read, :stack` only checks that the authenticated `ApiClient` has the string permission `"read:stack"` in its `permissions` array (see `ApiClient#check_permissions!`, `app/models/shipit/api_client.rb`) — it never checks that the requested `stack_id` matches `current_api_client.stack_id`. As a result, the equality the token is supposed to enforce, `stack_id ∈ {token.stack_id}` (or "all stacks" if unscoped), is violated: for the ccmenu endpoint the actual set becomes `stack_id ∈ Stack.all` for any client holding `read:stack`, scoped or not.

### Impact Explanation
Before the attacker's request: an `ApiClient` such as `here_come_the_walrus` is deliberately scoped (`stack: shipit`, see `test/fixtures/shipit/api_clients.yml`) so it can only see/read one specific stack via the standard API (`DeploysController#index`, `StacksController#show`, etc., all of which use the scoped `stack`/`stacks` helper). After the request: that same token, presented to `GET /ccmenu/*stack_id`, can retrieve the CI/deploy status (name, `lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`) of *any* stack in the installation, including stacks that belong to entirely different, unrelated repositories the token was never granted access to. This is an unauthenticated-for-that-resource read of stack state (deploy/build status), matching the "High - unauthenticated read of stack state, task streams or deploy output" impact bucket, because it grants read access to stack state outside of the credential's authorized scope.

### Likelihood Explanation
Any holder of a legitimately-scoped, low-privilege `ApiClient` token with the `read:stack` permission (a routine permission, not privileged) can immediately exploit this by supplying a different `stack_id` in the URL — no additional access, secret knowledge, or race condition is required. The vulnerable code path is the default, always-mounted `ccmenu` API route (`config/routes.rb`), so this is reachable by any consumer holding any `read:stack`-permitted token.

### Recommendation
Make `CCMenuController#stack` resolve through the same scoped `stacks` relation used by `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the "token authorizes stack X" binding is enforced consistently for the ccmenu endpoint just as it is for the rest of the JSON API.

### Proof of Concept
1. Create two stacks: `stack_a` (repo `org-a/private-repo`) and `stack_b` (repo `org-b/other-repo`).
2. Create an `ApiClient` scoped to `stack_a` only, with permission `read:stack` (mirrors fixture `here_come_the_walrus`).
3. Confirm scoping works for the normal API: `GET /api/stacks/org-b/other-repo/<env>` with that token's Basic Auth credentials returns 404/empty because `stacks` is filtered to `stack_a`'s id.
4. Call `GET /ccmenu/org-b/other-repo/<env>?token=<stack_a-scoped token>` — because `CCMenuController#stack` uses `Stack.from_param!` (unscoped) and `authenticate_api_client` only validates the token exists, the request succeeds and returns `stack_b`'s CI/deploy status (`lastBuildStatus`, `lastBuildLabel`, etc.), which the token was never authorized to see. [3](#0-2) [1](#0-0) [4](#0-3)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-39)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
    end
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

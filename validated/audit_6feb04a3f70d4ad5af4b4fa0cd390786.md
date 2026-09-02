### Title
CCMenu endpoint bypasses `ApiClient#stack_id` scoping, exposing any stack's deploy status/output to any `read:stack` token - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` defines its own private `stack` method that resolves the target stack directly via `Stack.from_param!(params[:stack_id])`, completely bypassing `BaseController#stacks`/`BaseController#stack`, which restricts lookups to `current_api_client.stack_id` when the client is scoped to a single stack. As a result, an `ApiClient` token that was issued (or intended) for a single stack can be used to fetch `ccmenu.xml` for any other stack, exposing its `deploys_and_rollbacks.last` status/output metadata.

### Finding Description
The intended binding is: `stack.id == current_api_client.stack_id` whenever `current_api_client.stack_id?` is true — i.e., a scoped token must only ever resolve stacks belonging to the stack it was scoped to. `BaseController` implements this correctly: [1](#0-0) 

`Shipit::Api::StacksController` relies on this scoped `stacks`/`stack` helper for `show`, `update`, `destroy`, etc.: [2](#0-1) 

However, `CCMenuController` overrides `stack` with an unscoped lookup that ignores `current_api_client.stack_id` entirely: [3](#0-2) 

`require_permission :read, :stack` only checks that the token's `permissions` array contains `"read:stack"` via `ApiClient#check_permissions!`; it performs no per-record scoping: [4](#0-3) 

So any `ApiClient` with `read:stack` in its `permissions` — including one created with a specific `stack_id` (intended to be scoped to one repository/org) — can supply an arbitrary `params[:stack_id]` for a different stack belonging to an unrelated `Repository#owner`, and `CCMenuController#show` will render that stack's `deploys_and_rollbacks.last.output`/status in the XML response: [5](#0-4) 

No other guard intervenes: `authenticate_api_client` only verifies the token signature, not stack scope, and there's no `require_permission!` check tying the operation to the specific stack. The equality `current_api_client.stack_id == stack.id` (enforced elsewhere in the app) is silently dropped in this controller.

### Impact Explanation
An attacker holding any single valid CCMenu token with `read:stack` — even one deliberately scoped by an operator to a single, low-sensitivity stack — can enumerate/guess other stacks' `to_param` values and retrieve their latest deploy/rollback status and output text via `GET /stacks/:stack_id/ccmenu.xml?token=...`, regardless of which `Repository#owner` (organization) that stack belongs to. This is a cross-tenant unauthorized read of stack state and deploy output, matching the "High - unauthenticated read of stack state, task streams or deploy output" category (here effectively unauthenticated-by-scope, since the token grants no legitimate access to that stack). It is repeatable against any stack in the installation and is not limited to the token owner's org.

### Likelihood Explanation
Preconditions are minimal: the attacker only needs one legitimate `ApiClient` token with `read:stack` permission (which could be scoped to their own, unrelated stack) and knowledge or guessability of another stack's `to_param` (owner/name/branch/env-derived identifier, not a secret). No GitHub session, webhook secret, or elevated Shipit role is required — this fits squarely within the stated attacker capability (anyone holding one `read:stack` CCMenu token). The attack is a single unauthenticated-by-scope HTTP GET, trivially repeatable.

### Recommendation
Make `CCMenuController#stack` use the scoped `stacks` lookup from `BaseController` (i.e., remove the private `stack` override, or change it to `@stack ||= stacks.from_param!(params[:stack_id])`) so that a stack-scoped `ApiClient` cannot resolve stacks outside its `stack_id`.

### Proof of Concept
minitest plan (in `test/controllers/api/ccmenu_controller_test.rb`):
1. Create `repo1 = Repository.create!(owner: "org1", name: "repoA")`, `stack1 = Stack.create!(repository: repo1, branch: "main")`, and a deploy/rollback on `stack1` with distinguishable `output` (e.g., `"SECRET-ORG1-OUTPUT"`).
2. Create `repo2 = Repository.create!(owner: "org2", name: "repoB")`, `stack2 = Stack.create!(repository: repo2, branch: "main")`, with its own deploy containing `"SECRET-ORG2-OUTPUT"`.
3. Create an `ApiClient` scoped to `stack1` (`api_client = ApiClient.create!(creator: user, name: "org1-token", permissions: ["read:stack"], stack: stack1)`).
4. Assert the binding before exploiting: `assert_equal stack1.id, api_client.stack_id`.
5. `get :show, params: { stack_id: stack2.to_param, token: api_client.authentication_token }`.
6. Assert `response.status == 200` and `response.body.include?("SECRET-ORG2-OUTPUT")` (or equivalent lastBuildStatus/output assertion derived from `stack2`'s deploy), proving `stack.id != api_client.stack_id` yet access was granted — the binding is broken.
7. Contrast with `Shipit::Api::StacksController#show` under the same scoped token and `params: { id: stack2.to_param }`, which should correctly 404/403 due to `stacks.from_param!` scoping, demonstrating the divergence is specific to `CCMenuController`.

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

**File:** app/controllers/shipit/api/stacks_controller.rb (L87-89)
```ruby
      def stack
        @stack ||= stacks.from_param!(params[:id])
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

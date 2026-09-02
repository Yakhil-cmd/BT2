### Title
CCMenuController#stack bypasses token-scoped stack lookup, enabling cross-tenant stack read - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController#stack` scopes stack lookup through `stacks.from_param!`, where `stacks` is restricted to `Stack.where(id: current_api_client.stack_id)` when the token is scoped. `Shipit::Api::CCMenuController` overrides `#stack` to call `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, so a token scoped to one stack can read any other stack's CCTray status via this endpoint.

### Finding Description
The binding that should hold is: `CCMenuController#stack == BaseController#stack`, i.e. both should resolve via `stacks.from_param!(params[:stack_id])` where `stacks` is `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0) . Instead, `CCMenuController` defines its own private `#stack` that calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` class, ignoring `current_api_client.stack_id` entirely [2](#0-1) .

Control comparison confirms the framework itself scopes correctly: `HooksController#stack_id` calls `stack.id`, which resolves through the inherited `BaseController#stack` -> `stacks.from_param!`, so `GET /api/stacks/:victim_stack/hooks?token=<scoped_token>` 404s because the victim stack is absent from `Stack.where(id: current_api_client.stack_id)` [3](#0-2) [4](#0-3) .

Exploit flow: attacker holds a token scoped to their own stack (`current_api_client.stack_id` set). They call `GET /api/stacks/:victim_stack_id/ccmenu.xml?token=<attacker_token>`. `CCMenuController#show` calls `stack` which calls `Stack.from_param!(params[:stack_id])` — this succeeds for the victim stack since it bypasses the `Stack.where(id: current_api_client.stack_id)` scoping [5](#0-4) . The response renders `deploys_and_rollbacks.last` state (branch, last deploy status, last commit) for the victim's stack, which the attacker's token has no authorization for. `require_permission :read, :stack` only checks permission against the token's own scope object, not against the specific `stack` instance being rendered, so it does not catch this divergence [6](#0-5) .

### Impact Explanation
An attacker with a token scoped to their own stack can read another tenant's stack state — including deploy/rollback status and identifying info exposed by the CCTray XML — for any arbitrary victim stack ID, with no rate limiting on repeated calls across different stack IDs. This is an unauthenticated (relative to scope) cross-tenant read of stack state, matching the High severity category "unauthenticated read of stack state."

### Likelihood Explanation
Precondition is only a valid `ApiClient` token scoped to any single stack (a normal, low-privilege credential many integrators hold) and knowledge/guessing of a victim `stack_id`/param. No GitHub secrets, session, or elevated role required. Attacker cost is a single unauthenticated (scope-wise) HTTP GET, fully repeatable against arbitrary stacks.

### Recommendation
Remove the overriding `#stack` method in `Shipit::Api::CCMenuController` and rely on the inherited `BaseController#stack` (`stacks.from_param!`), so the CCMenu endpoint is subject to the same `current_api_client.stack_id` scoping as every other API controller.

### Proof of Concept
Minitest plan (no live GitHub calls):
1. Create `stack_a` and `stack_b` (`Shipit::Stack`), and an `ApiClient` scoped to `stack_a` (`stack_id: stack_a.id`).
2. `GET /api/stacks/#{stack_b.to_param}/hooks?token=<client.token>` — assert response status `404` (control, confirms `HooksController` correctly scoped via `stacks.from_param!`).
3. `GET /api/stacks/#{stack_b.to_param}/ccmenu.xml?token=<client.token>` — assert response status `200` and body references `stack_b`'s state, demonstrating the divergence and cross-tenant read via `CCMenuController#stack`'s use of unscoped `Stack.from_param!`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-6)
```ruby
      require_permission :read, :stack
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

**File:** app/controllers/shipit/api/hooks_controller.rb (L50-52)
```ruby
      def stack_id
        stack.id if params[:stack_id].present?
      end
```

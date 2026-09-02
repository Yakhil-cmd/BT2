### Title
Cross-tenant deploy status/output disclosure via CCMenu endpoint bypassing per-token stack scoping - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` overrides `BaseController#stack` and resolves the target stack via `Stack.from_param!(params[:stack_id])` against the entire `Stack` table, instead of the tenant-scoped `stacks` relation used everywhere else in the API. Any `ApiClient` token carrying the `read:stack` permission — even one explicitly minted for a single stack via `ApiClient#stack_id` — can fetch the CCMenu XML (deploy status/output metadata) for any stack in the installation, including stacks owned by unrelated GitHub organizations.

### Finding Description
The intended binding is: `current_api_client.stack_id (if present) == stack.id` for the record being rendered. This is enforced generically in `BaseController`: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client has been scoped to a specific stack, and `stack` resolves `params[:stack_id]` only within that restricted set.

`CCMenuController` bypasses this entirely by redefining `stack`: [2](#0-1) 

This calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, so `current_api_client.stack_id` is never consulted. `#show` then renders whichever stack was resolved: [3](#0-2) 

The only guard applied is the coarse-grained permission check `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`: [4](#0-3) 

This only checks that `"read:stack"` is present in the token's `permissions` array; it never compares `operation`/`scope` against `stack_id`, so it does not close the gap the `stack` override creates. `ApiClient` supports being scoped to a single stack (`belongs_to :stack, optional: true`) — the entire point of `stack_id` scoping in `BaseController#stacks` — but `CCMenuController` silently drops that scoping.

Attacker flow: obtain (or already legitimately hold) any valid `ApiClient` token with `read:stack` permission, scoped to stack A in org 1. Send `GET /:owner/:repo/ccmenu.xml?token=<token>` (or via Basic Auth) with `stack_id` pointing at stack B belonging to org 2. `authenticate_api_client` in the controller succeeds because the token itself is valid, `require_permission` passes because the token has `read:stack`, and `stack` resolves stack B unconditionally, so `deploys_and_rollbacks.last.output`/status for org 2's stack is rendered to org 1's token holder.

### Impact Explanation
An `ApiClient` token intentionally scoped to one stack/org can read deploy status and (via the rendered CCMenu XML, which includes `lastBuildStatus`/`lastBuildLabel`/`activity` derived from `deploy.output`/state) metadata for any other stack in the Shipit installation, including private/internal stacks belonging to unrelated organizations. This is an unauthenticated-by-scope read of stack/deploy state, repeatable for every stack ID an attacker can guess or enumerate (stack params/IDs are often predictable `owner/repo/env` slugs), and matches the High severity category ("unauthenticated read of stack state, task streams or deploy output").

### Likelihood Explanation
Preconditions: the attacker must already hold one valid `ApiClient` token with `read:stack` permission (this could be a token deliberately scoped to a single low-privilege stack, as `stack_id` scoping is a supported/documented feature specifically to limit a token's blast radius). Given that, the attack requires only a single unauthenticated-in-scope HTTP GET to `.../ccmenu.xml` with an arbitrary `stack_id`; no GitHub secrets, session, or elevated role are needed. Feasibility is high and the request is trivially repeatable across stacks.

### Recommendation
Change `CCMenuController#stack` to use the tenant-scoped resolution already implemented in `BaseController`, i.e. remove the override (or reimplement it as `stacks.from_param!(params[:stack_id])`) so that `current_api_client.stack_id` scoping is honored consistently with every other API controller.

### Proof of Concept
Minitest plan (`test/controllers/api/ccmenu_controller_test.rb`):
1. Create `stack_a` with `Repository.new(owner: "org1", name: "repo1")` and `stack_b` with `Repository.new(owner: "org2", name: "repo2")`.
2. Create a deploy/rollback on `stack_b` with distinctive `output` (e.g. `"SECRET_ORG2_OUTPUT"`).
3. Create an `ApiClient` with `permissions: ["read:stack"]` and `stack: stack_a` (i.e. `stack_id` set to `stack_a.id`), simulating a token deliberately scoped to org 1 only.
4. `get :show, params: { stack_id: stack_b.to_param, token: client.authentication_token }`.
5. Assert `response.status == 200` and `response.body.include?("SECRET_ORG2_OUTPUT")` (or the corresponding `lastBuildStatus`/`lastBuildLabel` for `stack_b`), proving the org-1-scoped token retrieved org 2's deploy data — violating `current_api_client.stack_id (stack_a.id) == stack.id (stack_b.id)`.
6. Contrast with `Api::StacksController` or `Api::TasksController` under the same scoped token/`stack_id` combination returning 404, to show `BaseController#stacks` correctly enforces the binding elsewhere while `CCMenuController` does not.

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

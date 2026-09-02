## Title
API token's stack-scope binding is bypassed in `CCMenuController#show`, allowing read of any stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
This is a valid analog to the Solana PDA-constraint bug. The root cause pattern is identical: an authorization-relevant constraint (which PDA seeds must derive an account / which stack an `ApiClient` token is scoped to) is enforced in one code path but silently skipped in a sibling instruction/controller that accepts the same logical resource identifier. In shipit-engine, `Shipit::Api::BaseController#stack` correctly narrows lookup to the scope authorized for the current `ApiClient`, but `Shipit::Api::CCMenuController` overrides `#stack` and looks the record up unscoped, breaking the binding "stack a token authorizes == stack it touches."

### Finding Description
Every other controller under `Shipit::Api::BaseController` resolves the target stack through the scoped helper: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the authenticated `ApiClient` is scoped to a single stack, and `stack` performs `stacks.from_param!(...)` — i.e., the token's authorized stack is enforced as an equality constraint before the record is returned.

`CCMenuController`, however, defines its own `stack` method that ignores this scope entirely: [2](#0-1) 

```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end

def authenticate_api_client
  @current_api_client = ApiClient.authenticate(params[:token])
  super unless @current_api_client
end
```

`Stack.from_param!` performs a global lookup with no client/scope filtering: [3](#0-2) 

The controller still calls `require_permission :read, :stack`, but `require_permission!` only checks that the token has the `read:stack` permission string — it never checks that `current_api_client.stack_id` (if set) matches the `stack_id` param: [4](#0-3) 

So an `ApiClient` that was deliberately provisioned scoped to one stack (`belongs_to :stack, optional: true`, `stack_id` on the record) is still able to hit `GET /api/stacks/:stack_id/ccmenu` for *any* other stack, because the overridden `stack` method never re-derives/validates that the requested `stack_id` equals the token's authorized `stack_id` — exactly analogous to a PDA-derived account being trusted without re-validating its seeds in a sibling instruction.

### Impact Explanation
This breaks the binding "stack a token authorizes == stack it touches." An `ApiClient` provisioned and handed out for use with a single stack (e.g., to a third-party CI dashboard, integration, or less-trusted team) can use its valid token to read the last build/deploy status (label, activity, status, web URL) of *every* stack in the Shipit instance, not just the one it was scoped to. This is an unauthorized/escalated read of stack state across stacks the token was never granted access to, matching the "High — escalation into `Shipit.github_teams` authorization, unauthenticated read of stack state, task streams or deploy output" impact category.

### Likelihood Explanation
Likelihood is high for anyone already holding a legitimately-scoped `ApiClient` token: the request requires only a valid token (no privileged account, no additional secret, no session) and a guessed/enumerated `stack_id` (which follows the predictable `owner/repo/environment` format used throughout the app, see `Stack#to_param`). No race condition or timing is needed — the bypass is deterministic per request.

### Recommendation
Remove the controller-local override of `stack` in `CCMenuController` (or make it call the scoped `stacks.from_param!` helper from `BaseController` instead of `Stack.from_param!` directly), so that the token's `stack_id` scope constraint is enforced consistently with every other API controller. As a defense-in-depth measure, `require_permission!`/`check_permissions!` could additionally assert `current_api_client.stack_id.nil? || current_api_client.stack_id == stack.id` for any scoped client.

### Proof of Concept
1. Create two stacks, `A` (`owner/repoA/production`) and `B` (`owner/repoB/production`).
2. Provision an `ApiClient` scoped to stack `A` only (`stack_id` set to `A.id`, permission `read:stack`), and obtain its `authentication_token`.
3. As the holder of that token, request:
   `GET /api/stacks/owner/repoB/production/ccmenu?token=<A's token>`
4. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` directly (bypassing `stacks.from_param!`), the request succeeds and returns stack `B`'s build/deploy status XML, even though the token was never authorized for stack `B`.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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
```

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```

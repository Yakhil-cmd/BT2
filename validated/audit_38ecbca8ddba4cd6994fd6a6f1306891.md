## Title
Stack-scoped `ApiClient` token grants CCMenu status read access to *any* stack, not just the authorized one - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` authenticates a request using a token-bound `ApiClient`, but resolves the target `Stack` with `Stack.from_param!(params[:stack_id])` instead of the scope-aware `stacks.from_param!` helper used by every other API controller. This breaks the binding between the stack a token is authorized for and the stack the request actually touches.

### Finding Description
Every other stack-scoped API controller (`Shipit::Api::StacksController`, `Shipit::Api::TasksController`, `Shipit::Api::OutputsController`, `Shipit::Api::HooksController`) resolves the target stack through `BaseController#stack`, which is built on top of `BaseController#stacks`: [1](#0-0) 

`stacks` restricts the queryable `Stack` set to `current_api_client.stack_id` when the authenticated `ApiClient` is scoped to a specific stack — this is the mechanism that enforces "a token authorized for stack A cannot see stack B".

`CCMenuController`, however, defines its own private `stack` method that skips this scoping entirely and looks the stack up straight from `Stack`: [2](#0-1) 

`require_permission :read, :stack` only checks that the `ApiClient#permissions` array contains the string `read:stack` — it never checks which stack the client is bound to: [3](#0-2) 

So the only place that is supposed to enforce "this token's `stack_id` must equal the requested stack" is the `stacks` scoping in `BaseController`, and `CCMenuController` bypasses it. A token created for one stack (e.g. via `Shipit::CCMenuUrlController#client`, which mints an `ApiClient` with `permissions: %w[read:stack]`) can be replayed against `GET /api/stacks/*stack_id/ccmenu?token=...` with any other stack's `stack_id` param and will successfully render that stack's CCMenu XML (deploy status, lock status, last build info).

### Impact Explanation
This is an authenticated cross-stack read: the equality the engine is supposed to guarantee — `ApiClient.stack_id == requested stack` — does not hold for this endpoint. A holder of any single-stack-scoped, read-only CCMenu token can enumerate the CI/deploy status (including whether a stack is locked/archived and its last build outcome) of every other stack in the Shipit instance, including stacks belonging to different repositories/teams the token holder was never granted access to. This matches the documented High-impact class "escalation into `Shipit.github_teams` authorization" / "unauthenticated [cross-scope] read of stack state" since the token's authorization boundary (one stack) is silently widened to all stacks.

### Likelihood Explanation
Exploitation requires only a valid, low-privilege `read:stack`-scoped `ApiClient` token (such as the ones the engine itself creates for the CCMenu integration via `CCMenuUrlController`) and knowledge/guessing of another stack's `owner/name/environment` triple, which is generally discoverable (repo names are public, environments are conventional like `production`/`staging`). No privileged account, TLS interception, or GitHub credentials are needed — only the token itself, which by design is meant to be embedded in third-party CI dashboards, increasing its exposure.

### Recommendation
Change `CCMenuController#stack` to use the scoped lookup like every other API controller:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This routes the lookup through `BaseController#stacks`, restoring the `current_api_client.stack_id` restriction.

### Proof of Concept
1. As a legitimate user with access to stack `myorg/repoA/production`, visit its CCMenu URL page; Shipit creates (or reuses) a `read:stack`-scoped `ApiClient` bound to that stack and returns a token via `CCMenuUrlController#client`. [4](#0-3) 
2. Take that `token` value and issue: `GET /api/stacks/otherorg/repoB/production/ccmenu?token=<token>`.
3. Because `CCMenuController#stack` calls `Stack.from_param!` directly instead of `stacks.from_param!`, the request succeeds and returns `repoB`'s deploy/lock status, even though the token's owning `ApiClient` is scoped to `repoA/production` only.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

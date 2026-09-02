### Title
Stack-scoped `ApiClient` token bypasses its `stack_id` binding in `Api::CCMenuController#stack`, allowing cross-stack read of deploy/build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController` restricts an `ApiClient` scoped to a specific stack (`current_api_client.stack_id?`) to only that stack via the `stacks`/`stack` helper methods. `Api::CCMenuController` overrides `#stack` and resolves it directly from `Stack.from_param!(params[:stack_id])`, completely bypassing that scoping. As a result, a token that is authorized (bound) to stack A can be replayed against any other stack B just by changing the `stack_id` URL segment, breaking the equality "stack a token authorises == stack it touches."

### Finding Description
`Api::BaseController#stacks` enforces that a scoped `ApiClient` can only see the stack it belongs to: [1](#0-0) 

`Api::CCMenuController`, however, defines its own `#stack` that ignores this scoping entirely and looks the stack up globally by URL param: [2](#0-1) 

Permission checking (`require_permission :read, :stack`) only validates that the token carries the `read:stack` permission string — it never checks that the requested stack matches the token's own `stack_id`: [3](#0-2) 

The most common way to obtain such a token is `CCMenuUrlController#client`, which mints a `read:stack`-permissioned `ApiClient` scoped to one particular stack and hands the caller a URL containing that token: [4](#0-3) 

Because `Api::CCMenuController#show` calls the overridden, unscoped `#stack` method, that same token — meant only for the one stack it was minted for — can be used with any `stack_id` value: [5](#0-4) 

This is the direct analog of the audited bug class: like `ibRatio` not being updated to match `totalSupply` in `Basket.sol#auctionBurn()` (breaking the accounting invariant between two values that are supposed to move together), here the `ApiClient`'s `stack_id` binding is supposed to gate every stack access uniformly, but one code path (`CCMenuController#stack`) diverges from the canonical enforcement path (`BaseController#stacks`), silently dropping the binding.

### Impact Explanation
Any holder of a stack-scoped, `read:stack`-permissioned CCMenu token (routinely distributed to third-party CI dashboards/build-status monitors) can enumerate and read the current deploy/build status (`merge_status`, running/build activity, last build time, stack name, stack URL) of every stack in the Shipit instance, not just the one they were granted access to. This matches the in-scope "High" impact category of unauthenticated read of stack state, since the requester has no rights over stacks other than the one their token was minted for.

### Likelihood Explanation
High. No privileged action, GitHub App credentials, or session is required — only possession of any single stack-scoped CCMenu token (these are routinely handed out to external CI status tools via `CCMenuUrlController#fetch`, and are visible in query strings/logs/history). The attack is a single URL parameter change (`stack_id`) on an otherwise legitimate, already-authenticated request.

### Recommendation
Make `Api::CCMenuController#stack` reuse the scoped `stacks` helper from `Api::BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so a stack-scoped token can never resolve a stack outside its own `stack_id`.

### Proof of Concept
1. Admin creates CCMenu credentials for `stack-A` via `GET /ccmenu/*stack-A` (`CCMenuUrlController#fetch`), which mints an `ApiClient` with `permissions: ['read:stack']` and `stack_id = stack-A.id`, and returns a URL containing `token`.
2. Attacker takes that token (from logs, a leaked monitoring URL, browser history, etc.) and issues `GET /api/stacks/*stack-B/ccmenu?token=<token>` for an arbitrary `stack-B` they have no rights to.
3. `Api::CCMenuController#authenticate_api_client` accepts the token (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the token has `read:stack` in its permission list, and `#stack` resolves `stack-B` directly via `Stack.from_param!`, ignoring `current_api_client.stack_id`.
4. The response renders `stack-B`'s deploy/build status (`lastBuildStatus`, `activity`, `lastBuildTime`, `webUrl`), which the token was never authorized to view.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

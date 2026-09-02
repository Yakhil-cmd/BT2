### Title
Unauthorized cross-stack read via `CCMenuController` bypassing ApiClient stack scoping - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::StacksController#stack` correctly scopes lookups through `stacks.from_param!`, which restricts the resolvable `Stack` to the one bound to the authenticated `ApiClient` when that client is stack-scoped: `stacks` returns `Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true. [1](#0-0) [2](#0-1) 

`Shipit::Api::CCMenuController`, however, overrides `stack` to resolve directly against the unscoped `Stack` relation, `Stack.from_param!(params[:stack_id])`, completely bypassing the `current_api_client.stack_id` restriction that `require_permission :read, :stack` does not itself enforce (`check_permissions!` only checks that `"read:stack"` is present in `permissions`, not which stack it applies to). [3](#0-2) [4](#0-3) 

### Finding Description
The equality that should hold is: **the stack a token authorizes == the stack the endpoint touches**. That is, for a stack-scoped `ApiClient` (`stack_id` set), every action gated behind `require_permission :read, :stack` should only ever resolve `stack` to that one row.

`ApiClient#check_permissions!` verifies only the coarse-grained permission string (e.g. `"read:stack"`); it has no notion of which stack the permission applies to. [4](#0-3) 

The narrowing to a single stack is done exclusively at the controller layer, via `BaseController#stacks`/`#stack`:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 

`Api::CCMenuController` re-defines `stack` to bypass this scoping entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [5](#0-4) 

This is the exact analog of the report's referral/partner-NFT bug class: a value that is supposed to be validated against an authorization binding (the referral address vs. an approved-referrer list; the partner-NFT id vs. a per-holder mint cap) is instead accepted unchecked from client-controlled input (`params[:stack_id]`), silently widening what the credential can touch. Here, the binding that should constrain `stack_id` — "must be `current_api_client.stack_id`" — is dropped.

Compounding this, `CCMenuUrlController#client` mints a brand-new `ApiClient` with global `permissions: %w[read:stack]` and **no `stack:` binding at all**, even though the intent of the "CCMenu URL" feature is to hand out a token scoped to a single stack's build status:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
``` [6](#0-5) 

So even a legitimately generated CCMenu token is unscoped by construction (no `stack_id`), and even if it had a `stack_id`, `Api::CCMenuController#stack` would ignore it anyway.

### Impact Explanation
Any holder of a `read:stack`-permissioned `ApiClient` token — including one deliberately scoped to a single stack via `ApiClient.stack` — can read build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock state, deploy history metadata) for **every** stack in the Shipit instance by simply varying `params[:stack_id]` against `GET /api/:stack_id/ccmenu`. This is an unauthenticated-relative-to-intended-scope read of stack state across repositories/environments the token holder was never meant to see, matching the "High - unauthenticated read of stack state" impact category.

### Likelihood Explanation
This requires only possession of any valid `ApiClient` token with `read:stack` permission (e.g. the CCMenu token normally embedded in a query string and handed to external CI dashboards, or a purpose-scoped token created for a single stack). No privileged account, webhook secret, or GitHub credential is needed — only enumerating/guessing other stacks' `to_param` values (slugs), which are generally low-entropy and often known (repo/environment names).

### Recommendation
Remove the `stack` override in `Api::CCMenuController` and rely on the inherited, scope-respecting `BaseController#stack` (i.e. `stacks.from_param!(params[:stack_id])`). Additionally, bind the token minted in `CCMenuUrlController#client` to the specific stack (`ApiClient.create_with(permissions: %w[read:stack], stack:)`) so the credential itself, not just the controller, enforces the single-stack binding.

### Proof of Concept
1. As a user with access to Stack A, visit the "CCMenu URL" feature, which calls `CCMenuUrlController#fetch` and returns a URL containing a `token` for a newly created `ApiClient` (permissions `["read:stack"]`, `stack_id: nil`). [7](#0-6) 
2. Use that token against `GET /api/:other_stack_slug/ccmenu` for Stack B, a stack the user has no access to.
3. `Api::CCMenuController#authenticate_api_client` authenticates the token via `ApiClient.authenticate(params[:token])`. [8](#0-7) 
4. `require_permission :read, :stack` only checks the permission string, not stack identity, and passes. [4](#0-3) 
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` against the full `Stack` table, returning Stack B's data, which is rendered in the XML response — an unauthorized cross-stack read. [9](#0-8)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-31)
```ruby
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
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-18)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end

    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

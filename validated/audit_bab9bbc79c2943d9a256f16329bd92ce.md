### Title
Cross-stack disclosure of stack/deploy state via `CCMenuController` bypassing an `ApiClient`'s `stack_id` authorization scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
This is the closest reachable analog to the DYAD report's bug class ("an action is performed through a path that never goes through the code responsible for enforcing the associated restriction"). In Shipit, `Api::BaseController` enforces per-`ApiClient` stack scoping through the `stacks`/`stack` helper pair, but `Api::CCMenuController` overrides `#stack` with a version that never consults that scoping.

### Finding Description
`Shipit::ApiClient` can be scoped to a single stack (`belongs_to :stack, optional: true`, `stack_id?`), and this scope is the mechanism that is supposed to bind "the stack a token authorises" to "the stack it touches." That binding is enforced centrally in `Api::BaseController`: [1](#0-0) 

`stacks` returns `Stack.where(id: current_api_client.stack_id)` when the client is scoped, and `stack` resolves `params[:stack_id]` only from that restricted relation. `ApiClient#check_permissions!` itself has no notion of stack scope — it only checks the `read:stack`/`write:stack`/etc. permission strings: [2](#0-1) 

`Api::CCMenuController`, however, overrides `#stack` to resolve directly against the global `Stack` model, bypassing the `stacks` scoping entirely: [3](#0-2) 

The controller's only authorization gate is the generic `require_permission :read, :stack` before_action, which — as shown above — only checks the permission string, not `stack_id`: [4](#0-3) 

The binding that breaks, expressed as an equality that should hold but doesn't:
`stack the token authorizes (current_api_client.stack_id) == stack the token can touch (params[:stack_id] resolved in #show)`

Before the pull request/model of scoped tokens was correctly enforced everywhere, this equality held via `BaseController#stack`. In `CCMenuController`, the right-hand side is resolved from the unfiltered `Stack` table, so any client holding *any* valid `ApiClient` credential with `read:stack` (even one deliberately scoped by an operator to exactly one stack, e.g. for a CI status badge) can supply an arbitrary `stack_id` and read data for a stack it was never granted access to.

### Impact Explanation
`CCMenuController#show` renders the CCTray/CCMenu XML for the requested stack — including the stack's latest deploy/rollback status (`stack.deploys_and_rollbacks.last`), lock status, and build result — for any stack in the installation, not just the one the credential's operator intended to expose. This is an authorization-scope escape: a credential deliberately restricted to a single stack (the entire purpose of `ApiClient#stack_id`) is silently promoted to read state for every stack hosted by the Shipit instance. This maps to the "unauthenticated/unauthorized read of stack state" High-impact category once the scoping guarantee is broken, since the scoped credential is effectively equivalent to an unscoped one for this endpoint.

### Likelihood Explanation
Likelihood is Medium: exploitation only requires possession of a validly-issued `ApiClient` token (any permission set including `read:stack`, and any or no `stack_id` scope), which is a normal, low-privilege credential operators commonly hand out narrowly-scoped for CI/status-badge integrations. No GitHub write access, no session, no private key, and no elevated permission bits are required — the attacker just needs to be a legitimate but intentionally-restricted API consumer targeting a `stack_id` outside their granted scope, and the exact controller override is present in `CCMenuController` on every Shipit installation running this code.

### Recommendation
Have `CCMenuController#stack` reuse the scoped `stacks` lookup from `BaseController` instead of hitting `Stack.from_param!` directly, e.g.:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This restores the invariant that a token's authorized stack set is exactly the set of stacks it can act on/read, consistent with the enforcement already present in `StacksController` and other API controllers that rely on `BaseController#stack`.

### Proof of Concept
1. Operator creates an `ApiClient` scoped to `stack: stack_a` with permission `read:stack` (intended only for `stack_a`'s CI badge integration).
2. Using that client's `authentication_token`, an attacker (or the legitimate holder of that narrowly-scoped credential) requests:
   `GET /api/1/:repo_owner_b/:repo_name_b/:environment_b/ccmenu.xml?token=<stack_a_scoped_token>`
   for `stack_b`, a stack the client was never scoped to.
3. `authenticate_api_client` succeeds via `ApiClient.authenticate(params[:token])` [5](#0-4)  and `require_permission :read, :stack` passes because the client does hold that permission string.
4. `#show` calls `stack` [6](#0-5) , which resolves `stack_b` directly via `Stack.from_param!`, ignoring `current_api_client.stack_id`, and returns `stack_b`'s deploy/lock status in the XML response — disclosure that should have been blocked by the client's stack scope.

<br>

Note: I was unable to independently verify the `ApiClient` table schema (e.g., presence of a DB-level uniqueness/foreign-key constraint on `stack_id`) or definitively confirm every other API controller correctly delegates to `BaseController#stack`, since `db/migrate/**` is out of scope and I did not locate `db/schema.rb` in the index. This does not affect the finding, which is based entirely on the in-scope controller/model code shown above.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L5-6)
```ruby
    class CCMenuController < BaseController
      require_permission :read, :stack
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L33-36)
```ruby
      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

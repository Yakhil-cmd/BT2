Confirmed. `CCMenuController#stack` in `app/controllers/shipit/api/ccmenu_controller.rb` bypasses the scoping enforced by `BaseController#stacks`/`BaseController#stack`, which restrict a stack-scoped `ApiClient` (`stack_id?` true) to `Stack.where(id: current_api_client.stack_id)`. The CCMenu controller instead calls `Stack.from_param!(params[:stack_id])` directly against the unrestricted `Stack` relation, so the `read:stack` permission check passes generically but the actual stack touched is whatever `params[:stack_id]` the caller supplies — not the stack the token is bound to.### Title
`CCMenuController#stack` bypasses per-token stack scoping, letting a stack-scoped `read:stack` `ApiClient` read any stack's build status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces a binding: an `ApiClient` that is scoped to a single stack (`stack_id?` true) must only ever be able to touch that one `Stack` record, via the `stacks`/`stack` helper methods. [1](#0-0) 
`Shipit::Api::CCMenuController`, however, overrides `stack` to resolve `params[:stack_id]` directly against the unscoped `Stack` relation, never consulting `current_api_client.stack_id`: [2](#0-1) 
This is the same bug class as the Lido `findCheckpointHints` report: a value that is supposed to bound what an authorized actor may act on (`current_api_client.stack_id`, analogous to `getLastCheckpointIndex()`) is silently replaced by an attacker-influenced value (`params[:stack_id]`, analogous to `requestsToClaim.length + 1`) that is *not* validated against the true bound before being used to fetch/act on data.

### Finding Description
`ApiClient#check_permissions!` only checks that the token has the generic `read:stack` permission string; it has no notion of *which* stack is being accessed: [3](#0-2) 
The per-stack restriction is supposed to be enforced entirely by the `stacks`/`stack` helpers in `BaseController`:
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
``` [1](#0-0) 
Every other API controller (e.g. `Shipit::Api::StacksController`) relies on this scoped `stack`/`stacks` method, so a token created with `stack: shipit` (i.e. `stack_id` set) can only fetch/act on that one stack.

`CCMenuController` requires only `:read, :stack` and defines its own private `stack` method that ignores the scoping entirely:
```ruby
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [4](#0-3) 
`Stack.from_param!` is a global, unscoped finder (used elsewhere, e.g. `app/models/shipit/stack.rb`), so any `stack_id`/slug supplied in the request is looked up across the entire `Stack` table, not just the stacks the presented token is entitled to.

Binding broken (as an equality):
- Intended: `stack_touched_by_ccmenu == stack_bound_to(current_api_client.stack_id)` when the client is stack-scoped.
- Actual: `stack_touched_by_ccmenu == Stack.from_param!(params[:stack_id])`, independent of `current_api_client.stack_id`.

This exactly mirrors the Lido issue where the `_lastIndex` bound that should equal `getLastCheckpointIndex()` was instead derived from attacker/caller-supplied `requestsToClaim.length + 1`, decoupling the value actually used from the value that was supposed to authorize/bound the operation.

### Impact Explanation
An `ApiClient` token that was deliberately minted and scoped to a single stack (e.g. via `Shipit::CCMenuUrlController#client`, which creates a `read:stack`-only, stack-scoped client for embedding in third-party CI dashboards: `app/controllers/shipit/ccmenu_url_controller.rb`) can be replayed with a different `stack_id` parameter to read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, lock status, etc.) of **any** stack in the Shipit instance, including stacks the token holder has no authorization to see. This is an unauthenticated-for-that-resource read of stack state — matching the High-impact category "unauthenticated read of stack state ... deploy output" defined in the rules, since the token is authenticated but never authorized for the specific stack it ends up reading.

### Likelihood Explanation
Exploitation only requires possession of any valid stack-scoped `read:stack` API token (these are routinely embedded in CI dashboard/CCMenu URLs, which are lower-trust, semi-public artifacts by design per `CCMenuUrlController`) and knowledge/guessing of another stack's `to_param` (repo/environment/branch slug, which is often predictable or discoverable via the stacks index). No privileged access, signature forgery, or session is needed beyond the existing scoped token itself.

### Recommendation
Make `CCMenuController#stack` use the inherited, scoped `stack`/`stacks` helper from `BaseController` instead of calling `Stack.from_param!(params[:stack_id])` directly, i.e. remove the private `stack` override (or have it delegate to `super`/`stacks.from_param!(params[:stack_id])`) so that stack-scoped tokens are restricted to their bound stack, consistent with every other API controller.

### Proof of Concept
1. Create (or obtain) a stack-scoped `ApiClient` with only `read:stack` permission bound to `stack_id = A` (this is exactly what `CCMenuUrlController#client` does for stack A: `app/controllers/shipit/ccmenu_url_controller.rb` lines 15-18).
2. Using that client's `authentication_token`, call `GET /api/stacks/:stack_id/ccmenu.xml` (routed to `CCMenuController#show`) but substitute `params[:stack_id]` with the identifier of a different stack `B` that the token was never scoped to.
3. `require_permission :read, :stack` succeeds because the client has the generic `read:stack` permission (unrelated to which stack is requested).
4. `stack` resolves via `Stack.from_param!(params[:stack_id])` (`app/controllers/shipit/api/ccmenu_controller.rb` lines 29-31), ignoring `current_api_client.stack_id`, and returns stack `B`.
5. The response renders `shipit/ccmenu/project` with stack `B`'s real deploy/build status, exposing information the token holder was never authorized to see.

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

### Title
Stack-scoped `ApiClient` token bypasses its own stack scope in the CCMenu API — token authorized for stack A reads status/output of any stack B - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`ApiClient` tokens can be scoped to a single `Stack` (`belongs_to :stack, optional: true`), and the generic scoping mechanism used across the JSON API restricts lookups to `current_api_client.stack_id` when present. `Shipit::Api::CCMenuController` overrides the shared `stack` accessor to bypass this scoping entirely, breaking the binding "the stack a token authorizes == the stack the request touches."

### Finding Description
`Shipit::Api::BaseController` defines the scope-respecting accessor used by every other API controller: [1](#0-0) 
`stacks` filters to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` is stack-scoped, and `stack` resolves the request's `stack_id` param through that scoped relation — so a client scoped to stack A can never resolve a stack B object via `stack`.

`Shipit::Api::CCMenuController`, however, overrides `stack` to bypass the scoped `stacks` collection entirely: [2](#0-1) 
It resolves `Stack.from_param!(params[:stack_id])` directly against the whole `Stack` table, ignoring `current_api_client.stack_id`.

Authorization on this controller is enforced only via `require_permission :read, :stack`, which delegates to `ApiClient#check_permissions!`: [3](#0-2) 
This method only checks that the permission string `"read:stack"` is present in the client's `permissions` array — it performs no comparison between `current_api_client.stack_id` and the requested `stack_id`. The only place that equality is normally enforced is the `stacks`/`stack` scoping in `BaseController`, which `CCMenuController` does not use.

The route confirms `stack_id` is attacker-controlled per request, independent of which token is presented: [4](#0-3) 

### Impact Explanation
An `ApiClient` token that was deliberately minted with a narrow scope (`stack_id` set to one specific stack, e.g. as documented/tested by the `here_come_the_walrus` fixture, or as produced for embedding in third-party CI dashboard integrations via `CCMenuUrlController`) is expected to only ever expose that one stack's build/deploy status. Because `CCMenuController#stack` ignores the scope, the holder of such a token can instead request `/api/stacks/*any_other_stack/ccmenu` and read that unrelated stack's latest deploy/rollback status (`running?`, `id`, `ended_at`, name, last build status/label) — an unauthorized cross-stack read of stack state, matching the "High - unauthenticated/unauthorized read of stack state" impact category. This is a direct instance of the reported bug class: a token's authorized scope (the stack it was bound to) is checked ("`read:stack` permission present") but the actual object acted upon (`stack_id` param) is never verified to be the one the token was bound to — exactly analogous to `RenegotiationOffer`'s signature being checked but not bound to which function/tranche it authorizes.

### Likelihood Explanation
Any party who legitimately possesses one stack-scoped CCMenu/API token (a fairly common, lower-privilege credential intentionally distributed to CI dashboard tools) can exploit this with a single unauthenticated-effort GET request, only changing the `stack_id` path segment. No secret material, GitHub credentials, or additional privilege is required beyond possession of a token meant to be restricted to one stack.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to resolve through the scoped `stacks` collection (i.e., remove the override and let it inherit `BaseController#stack`, or explicitly use `stacks.from_param!(params[:stack_id])`) so stack-scoped tokens cannot read data outside their authorized stack.

### Proof of Concept
1. As an authenticated Shipit user, create (or have created via `CCMenuUrlController#fetch`) an `ApiClient` with `permissions: ['read:stack']` and `stack: StackA`.
2. Using HTTP Basic auth with that client's `authentication_token`, issue:
   `GET /api/stacks/<StackB-owner>/<StackB-repo>/<StackB-env>/ccmenu`
   where `StackB` is a different, unrelated stack.
3. Observe the request succeeds (200 OK, `read:stack` permission check passes) and returns `StackB`'s latest deploy/rollback status via the `shipit/ccmenu/project` view — despite the token being scoped only to `StackA`, because `CCMenuController#stack` resolved `Stack.from_param!` unscoped instead of `stacks.from_param!`.

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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

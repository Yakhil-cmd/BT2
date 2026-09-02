### Title
Scoped API token bypasses stack authorization in CCMenu XML endpoint - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Api::CCMenuController#stack` resolves the target stack via `Stack.from_param!(params[:stack_id])` against `Stack.all`, whereas every other API controller (via `Api::BaseController#stack` / `Api::StacksController#stack`) resolves against the scoped `stacks` relation (`stacks.from_param!`). A token whose `stack_id` restricts it to one stack can therefore read CCMenu build-status XML for any other stack in the installation.

### Finding Description
The binding that should hold everywhere is:
`stack_touched ∈ stacks(current_api_client)`, where `stacks(current_api_client) = current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all` [1](#0-0)  .

`Api::StacksController` uses this scoped helper (`stacks.from_param!(params[:id])`) for its `stack` accessor, so a request for a foreign `stack_id` with a scoped token 404s [2](#0-1)  .

`Api::CCMenuController`, however, overrides `stack` to bypass the scope entirely:
```
def stack
  @stack ||= Stack.from_param!(params[:stack_id])
end
``` [3](#0-2) 

This queries `Stack.all`, not `stacks`, so the scoping condition on `current_api_client.stack_id` is never applied for this controller.

The only other guard on this action is `require_permission :read, :stack`, which calls `current_api_client.check_permissions!(operation, scope)`. That method only checks whether the string `"read:stack"` is present in the client's `permissions` array — it performs no per-stack ownership check at all [4](#0-3)  . So nothing downstream of `stack` compensates for the missing scope filter.

`Api::CCMenuController` also overrides `authenticate_api_client` to accept `params[:token]` directly (`ApiClient.authenticate(params[:token])`), a documented legacy feature for CI tools without HTTP Basic support [5](#0-4)  ; that alternate auth path is not itself the flaw — the flaw is solely that the resolved `@current_api_client` (however authenticated) is never used to scope the `stack` lookup.

Attack: attacker obtains (or is issued) a legitimate API token scoped to Stack A (`current_api_client.stack_id == A.id`). They send `GET /api/stacks/:owner/:repo/:env/cacc.xml?stack_id=<Stack B params>&token=<token>` (or with Basic auth) where Stack B belongs to a different repository/team. `Api::StacksController#show` for the same B id returns 404 because `stacks` is `Stack.where(id: A.id)`. `Api::CCMenuController#show` returns 200 with Stack B's build status, lock state, and last-deploy metadata rendered in `shipit/ccmenu/project` XML.

### Impact Explanation
A token scoped to one stack can read build/deploy state (branch head status, last build result/label/time, lock status) of any other stack in the Shipit instance, including stacks belonging to repositories the token holder has no legitimate access to. This is a cross-tenant/cross-repository authorization bypass limited to read of stack state (no write, no secret exfiltration, no command execution) — matching "High: unauthenticated/unauthorized read of stack state" since the scoping restriction that should make the token unauthorized for other stacks is bypassed. It's fully repeatable against any stack ID in the same Shipit deployment; the blast radius is every stack in the installation, not just the token's assigned one.

### Likelihood Explanation
Preconditions: attacker needs one valid API token with a restrictive `stack_id` (a common, low-privilege token configuration for CI integrations, e.g. issued to a single team/repo for CCMenu status). No GitHub credentials, no session, and no special permissions beyond `read:stack` are required — this is exactly the kind of token routinely embedded in CI build-monitor configs. Given such a token, the attacker only needs to guess or enumerate another stack's `stack_id`/param (stack IDs/slugs are low-entropy and often derivable from repo owner/name/environment), and the request is a single unauthenticated-cost HTTP GET. Highly feasible and trivially repeatable.

### Recommendation
Change `Api::CCMenuController#stack` to use the scoped relation like the rest of the API controllers:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
removing the direct `Stack.from_param!(params[:stack_id])` call against `Stack.all`, so the `current_api_client.stack_id` scope applies uniformly.

### Proof of Concept
Table-driven minitest in `test/controllers/api/ccmenu_controller_test.rb` style (added under `test/`, no live GitHub):
1. Create `stack_a` and `stack_b` (different repositories).
2. Create an `ApiClient` with `stack_id: stack_a.id` and `permissions: ['read:stack']`; obtain its `authentication_token`.
3. `get :show` on `Shipit::Api::StacksController` with `id: stack_b.to_param` and the token → assert `response.status == 404`.
4. `get :show` on `Shipit::Api::CCMenuController` with `stack_id: stack_b.to_param` and the same token → currently asserts `response.status == 200` and that the XML `name` attribute equals `stack_b.to_param`, proving disclosure of Stack B's data through a token scoped only to Stack A.
5. Assert the two responses diverge (404 vs 200) for the identical token/foreign-stack pair, demonstrating the broken `stack_touched ∈ stacks(current_api_client)` invariant.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L29-31)
```ruby
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

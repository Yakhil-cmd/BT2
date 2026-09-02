### Title
Cross-stack API token scope bypass in CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
An `ApiClient` token that is scoped to a single stack (`stack_id` set) is meant to only ever authorize access to that one stack, as enforced centrally by `Api::BaseController#stacks`/`#stack`. `Api::Ccmenu::Controller` overrides `#stack` and resolves the target stack directly from the URL parameter without going through the scoping filter, so a stack-scoped token can be used to read the build/deploy status of *any* stack in the Shipit instance, not just the one it was authorized for.

### Finding Description
`Api::BaseController` defines the canonical stack-resolution helpers used by every API controller to enforce token scoping: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id`, and `stack` is defined in terms of that scoped relation — this is the binding: `token.stack_id == stack.id` for stack-scoped tokens.

`Api::CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It resolves the stack directly via `Stack.from_param!(params[:stack_id])`, ignoring `current_api_client.stack_id`. The only authorization check performed is `require_permission :read, :stack`, which only checks that the token *has* the `read:stack` permission string — it does not check *which* stack that permission applies to.

The equality that should hold — `token.authorized_stack_id == stack.id` when the token is stack-scoped — is broken here: the token's authorized stack (the one bound at `ApiClient` creation, see `app/models/shipit/api_client.rb`) diverges from the stack actually touched by the request (any stack chosen by the caller via `params[:stack_id]`).

This directly parallels the reported bug class: a binding meant to keep two states in sync (Aave's actual position vs. Morpho's tracked position; here, the stack a token *authorizes* vs. the stack an endpoint *touches*) is enforced in the general path but not in this specific code path, letting privileged-for-one-scope state be used against a different scope.

### Impact Explanation
An attacker who holds (or obtains, e.g. via the `CCMenuUrlController#fetch` flow which embeds the token in a shareable URL, see `app/controllers/shipit/ccmenu_url_controller.rb`) a stack-scoped, read-only `ApiClient` token for Stack A can query `Api::CCMenuController#show` with `stack_id` set to Stack B to read Stack B's deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, lock status, etc.), even though the token was never authorized for Stack B. This is an unauthorized cross-stack read of stack state, matching the "High: unauthenticated/unauthorized read of stack state" impact category — a token meant to be confined to one stack's state leaks state belonging to every other stack in the deployment.

### Likelihood Explanation
Exploitation only requires possession of any valid, stack-scoped, `read:stack`-permissioned API token (these are routinely created for CI dashboards/CCMenu integrations and shared as URLs by `CCMenuUrlController`) plus knowledge of another stack's identifier (stack identifiers are predictable — `owner/repo/environment`-style params, see `Stack.from_param!`). No additional privilege or secret is needed beyond a token that is already expected to be shared/embedded for this exact feature, making this readily reachable.

### Recommendation
Have `Api::CCMenuController#stack` resolve through the scoped `stacks` relation from `BaseController` (i.e., remove the override, or reimplement it as `stacks.from_param!(params[:stack_id])`) so the `current_api_client.stack_id` restriction is enforced consistently for this endpoint as it is everywhere else.

### Proof of Concept
1. Create (or use) two stacks, e.g. `shipit_stacks(:shipit)` (Stack A) and `shipit_stacks(:soc)` (Stack B).
2. Create an `ApiClient` scoped to Stack A only with `permissions: ['read:stack']` (`ApiClient.create!(creator: user, name: 'scoped', stack: stack_a, permissions: ['read:stack'])`), analogous to fixture `here_come_the_walrus` used in [3](#0-2) .
3. Send `GET /api/:stack_b_id/ccmenu.xml?token=<stack_a_scoped_token>` (or via Basic Auth) targeting Stack B's `stack_id` in the URL.
4. Because `Api::CCMenuController#stack` at [4](#0-3)  calls `Stack.from_param!` unscoped, the request succeeds and returns Stack B's build/deploy XML status, despite the token only being authorized (`stack_id`) for Stack A.

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

**File:** test/controllers/api/stacks_controller_test.rb (L217-223)
```ruby
      test "an api client scoped to a stack will only see that one stack" do
        authenticate!(:here_come_the_walrus)
        get :index
        assert_json do |stacks|
          assert_equal 1, stacks.size
        end
      end
```

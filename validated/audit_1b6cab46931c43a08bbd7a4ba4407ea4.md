Found the analog. `Api::CCMenuController` overrides `authenticate_api_client` to accept a token passed as a plain query-string parameter instead of the `Basic` auth header used everywhere else, but then resolves the target stack with the global `Stack.from_param!` rather than through the token-scoped `stacks` collection used by the base controller (`stacks.from_param!`, which restricts to `current_api_client.stack_id` when the client is scoped).

### Title
CCMenu API endpoint lets a stack-scoped `ApiClient` token read any stack, not just the one it authorizes - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`ApiClient` tokens can be scoped to a single stack (`ApiClient#stack_id`), and the base API controller enforces that scoping by looking stacks up through `stacks` (`Stack.where(id: current_api_client.stack_id)`) rather than the global `Stack` table. `Api::CCMenuController`, however, defines its own `stack` method that calls `Stack.from_param!` directly on the unscoped `Stack` model, bypassing the very scoping mechanism the token was created with.

### Finding Description
The intended binding is: *the stack a token authorizes* == *the stack a token can touch*. `Api::BaseController#stacks` enforces this: [1](#0-0) . Every other stack-scoped API controller (locks, merge_requests, tasks, deploys, hooks) relies on this `stack`/`stacks` helper, so a token created via `CCMenuUrlController#client` with `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` and bound to one stack [2](#0-1)  is supposed to only be able to read that stack.

`CCMenuController` breaks this binding by redefining `stack` to call `Stack.from_param!(params[:stack_id])` directly, ignoring `current_api_client.stack_id`, and by redefining `authenticate_api_client` to accept the token from `params[:token]` in the URL instead of the HTTP `Authorization` header: [3](#0-2) . Because the `token` created for one stack is only checked with `ApiClient.authenticate(token)` — which verifies the signature and permission list (`read:stack`), not the `stack_id` binding — a caller who obtains a scoped CCMenu token can supply any `stack_id` in the URL of the `show` action and read deploy status information for a different stack than the one the token was minted for.

### Impact Explanation
This is an authorization/scoping bypass: unauthenticated read of stack state (build status, deploy metadata) for any stack in the installation, using a token that was only supposed to authorize reads for one stack. Per the accepted-impact list this constitutes "unauthenticated read of stack state" for stacks outside the token's authorized scope — the token itself is unprivileged relative to those other stacks. It does not by itself yield RCE or credential exfiltration, but it crosses the "stack a token authorizes" vs "stack a token touches" trust boundary called out in the rules.

### Likelihood Explanation
CCMenu tokens are deliberately embedded in an unauthenticated-looking client-consumable URL (`/ccmenu/*stack_id`, `CCMenuUrlController#fetch`), designed to be shared with CI dashboard tools; such URLs are lower-sensitivity by design and easily leaked/logged/proxied. Once such a URL/token leaks, exploiting the flaw only requires changing the `stack_id` path segment — no additional secrets or privileges are required, making exploitation straightforward once a single valid CCMenu token is obtained.

### Recommendation
In `Api::CCMenuController#stack`, use the token-scoped `stacks` collection from `BaseController` (`stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` on the unscoped model, so a stack-scoped token cannot be used to read other stacks.

### Proof of Concept
1. Visit a stack overview page as an authenticated Shipit user and trigger `GET /ccmenu/<org>/<repo>/<env>` (`CCMenuUrlController#fetch`), which creates/returns a `read:stack` `ApiClient` scoped to that one stack and returns a URL like `/api/stacks/<org>/<repo>/<env>/ccmenu?token=<TOKEN>`.
2. Reuse that same `<TOKEN>` against a different stack the token was never scoped to: `GET /api/stacks/<other-org>/<other-repo>/<other-env>/ccmenu?token=<TOKEN>`.
3. Observe that `Api::CCMenuController#authenticate_api_client` accepts the token (valid signature, `read:stack` permission present) and `#stack` resolves the *other* stack via the unscoped `Stack.from_param!`, returning that stack's build/deploy status — even though the token was only meant to authorize the original stack.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
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

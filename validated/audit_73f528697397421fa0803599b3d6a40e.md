## Title
CCMenu Controller Bypasses Per-Stack ApiClient Scoping, Allowing a Stack-Restricted Token to Read Any Stack's Deploy State - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method used by every other API controller, replacing the scope-respecting `stacks.from_param!` with an unscoped `Stack.from_param!`. This breaks the binding between "the stack a token authorizes" (`ApiClient#stack_id`) and "the stack the request actually touches" (`params[:stack_id]`), letting any holder of a stack-restricted, read-only `ApiClient` token read the CI/deploy status of every stack in the installation, not just the one the token was scoped to.

### Finding Description
`Shipit::Api::BaseController` is designed so that `ApiClient` tokens can be scoped to a single stack. The `stacks` scope enforces this: [1](#0-0) 

`require_permission!`/`check_permissions!` only checks that the client holds the coarse `"read:stack"` permission string; it never checks `current_api_client.stack_id` against the requested stack: [2](#0-1) 

The actual stack-scoping enforcement therefore relies entirely on controllers calling `stack`/`stacks` from `BaseController`. `Api::CCMenuController` instead defines its own `stack` method that ignores the client's scope entirely: [3](#0-2) 

Because `require_permission :read, :stack` (declared at the top of `CCMenuController`) only validates the permission string and `stack` is resolved via `Stack.from_param!(params[:stack_id])` rather than `stacks.from_param!(params[:stack_id])`, any valid `ApiClient` token with `read:stack` permission — even one legitimately created and scoped to a single stack (e.g. via `stack_id` as in the `here_come_the_walrus` fixture, or a per-stack CCMenu token from `Shipit::CCMenuUrlController#client`) — can be replayed against `/api/stacks/<any-other-stack>/ccmenu.xml?token=...` to read that other stack's CCMenu status.

This is the same trust-binding failure described in the report: a caller is meant to be constrained to the values/scope the issuer computed (`storageRate`/costable-wallet batch calculated on-chain vs. arbitrary parameters passed to `batchSend`), but the enforcement point (`getCostableWalletBatch`) is bypassable because the constrained operation (`batchSend`) doesn't call back into it. Here, the constrained operation (`CCMenuController#show`) doesn't call back into the scope-enforcing `stack`/`stacks` helper that the rest of the API relies on.

### Impact Explanation
An attacker who legitimately possesses (or is issued) a stack-scoped, read-only API token — the same class of low-privilege credential the app hands out for CI badges (`CCMenuUrlController`) — can escalate that token's authority to read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, lock state, etc., per `test/controllers/api/ccmenu_controller_test.rb`) of arbitrary stacks across the whole Shipit installation, including stacks belonging to repositories/teams the token holder has no legitimate access to. This is an authorization-scope escalation exposing stack/deploy state outside the token's intended boundary.

### Likelihood Explanation
Exploitation only requires a valid, low-privilege `ApiClient` token restricted to one stack (routinely generated for integrations such as CI badges) and knowledge/guessing of another stack's identifier (stack names/slugs are not secret and are visible throughout the UI/URLs). No webhook secret, GitHub App key, or elevated account is needed — only a token that the application itself considers "read-only, single-stack scoped."

### Recommendation
Make `Api::CCMenuController#stack` reuse the scope-aware helper from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the per-client `stack_id` restriction is enforced consistently. More generally, move stack-scope enforcement into `check_permissions!`/`require_permission!` itself (comparing `current_api_client.stack_id` against the resolved stack) so future controllers cannot silently bypass it by defining their own `stack` method.

### Proof of Concept
1. Create/obtain an `ApiClient` scoped to `stack_id: A` with `permissions: ["read:stack"]` (e.g. the `here_come_the_walrus` fixture pattern, or a token minted by `Shipit::CCMenuUrlController#fetch` for stack A).
2. Confirm scoping works normally: `GET /api/stacks/A.json` succeeds, `GET /api/stacks/B.json` is excluded because `Api::StacksController` uses `stacks.from_param!` (via `BaseController#stack`), respecting `current_api_client.stack_id`.
3. Call the CCMenu endpoint for a different stack B using the token scoped to A: `GET /api/stacks/B/ccmenu.xml?token=<token-scoped-to-A>`.
4. Because `Api::CCMenuController#stack` uses `Stack.from_param!` (unscoped), the request succeeds and returns stack B's `lastBuildStatus`/`lastBuildLabel`/lock state, despite the token only being authorized for stack A.

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

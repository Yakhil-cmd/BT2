### Title
Cross-stack read of stack/deploy state via unscoped `stack` lookup in `CCMenuController` - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` authenticates callers with a per-stack `ApiClient` token passed as a query-string parameter, but resolves the target stack with an **unscoped** `Stack.from_param!` lookup instead of the client-scoped lookup used everywhere else in the API. This breaks the binding "the stack a token authorizes == the stack the endpoint touches," letting a token that was only ever meant to unlock a single stack's CI status be replayed against `stack_id` values for arbitrary other stacks.

### Finding Description
Every other API controller resolves the target stack through `BaseController#stack`, which is deliberately restricted to the stacks the authenticated `ApiClient` is scoped to: [1](#0-0) 

`stacks` filters by `current_api_client.stack_id` when the client is scoped to one stack, so `stacks.from_param!(params[:stack_id])` will raise/404 if a scoped token is used against a `stack_id` outside its allowance.

`CCMenuController`, however, overrides `stack` and bypasses this scoping entirely: [2](#0-1) 

It only checks `require_permission :read, :stack` — an operation-level permission — never that the resolved stack matches `current_api_client.stack_id`. The per-stack CCMenu token is created and handed out specifically for one stack: [3](#0-2) 

That design intent (one token → one stack, exposed unauthenticated via `?token=` for CI-monitoring tools like CCMenu clients) is exactly the boundary `Api::BaseController#stack` is supposed to enforce, but `CCMenuController#stack`'s `Stack.from_param!(params[:stack_id])` call ignores `current_api_client.stack_id` and resolves any stack in the installation.

**Binding broken:** `current_api_client.stack_id == params[:stack_id]` (enforced in `BaseController#stack`) vs. `params[:stack_id]` unconditionally accepted in `CCMenuController#stack`.

Before the attacker's request: a "here_come_the_walrus"-style `ApiClient` fixture is scoped to stack `shipit` with only `read:stack` permission — it is trusted to read only that stack.
After the attacker's request: the same token, sent with a different `stack_id` in the URL, returns build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock reason) for any other stack in the Shipit instance, including private/other-team repositories the token was never authorized for.

### Impact Explanation
This is an unauthenticated (relative to the target stack) read of stack state and deploy status across stacks/repositories that the token holder was not authorized to see — matching the High-severity category "unauthenticated read of stack state, task streams or deploy output." Because CCMenu tokens are routinely distributed to third-party CI dashboard tools and embedded in URLs, leakage of one such token grants visibility into every stack managed by the Shipit instance, not just the one it was minted for.

### Likelihood Explanation
Likelihood is meaningfully high: CCMenu tokens are intentionally exposed via unauthenticated query-string URLs for integration with external CI status tools (that's their entire purpose per `CCMenuUrlController`), so they are more likely to leak (browser history, logs, proxies, shared dashboards) than Basic-Auth API tokens. No privileged access or additional exploit is needed beyond substituting `stack_id` in the request — the attacker just needs one leaked/legitimate CCMenu token for any stack.

### Recommendation
Change `Shipit::Api::CCMenuController#stack` to use the scoped lookup consistent with the rest of the API:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the enforcement already implemented in `Api::BaseController#stacks`/`#stack`, ensuring a stack-scoped token can only ever resolve the stack it was issued for.

### Proof of Concept
1. Have an `ApiClient` scoped to `stack_id: <shipit_stack>` with `read:stack` permission (as created by `CCMenuUrlController#client` when a legitimate user requests a CCMenu URL for stack A).
2. Use the resulting token to call:
   `GET /api/stacks/:other_stack_id/ccmenu.xml?token=<token>`
   substituting `other_stack_id` for a different stack the token was never scoped to.
3. `CCMenuController#authenticate_api_client` accepts the token (it is valid), `require_permission :read, :stack` passes (permission exists), and `CCMenuController#stack` resolves `other_stack_id` via unscoped `Stack.from_param!`, returning that unrelated stack's build/deploy status in the XML response — confirming cross-stack disclosure with a token authorized for a single, different stack.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

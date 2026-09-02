### Title
CCMenu API endpoint ignores per-stack token scoping, letting a stack-scoped CCMenu credential read any stack's build state - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` authenticates a caller with a stack-scoped `ApiClient` token but then resolves the target `stack` directly from `Stack.from_param!(params[:stack_id])`, bypassing the scoping enforced everywhere else in the API. This breaks the binding "a stack a token authorizes versus a stack it touches."

### Finding Description
`CCMenuUrlController#fetch` mints a low-privilege, stack-scoped `ApiClient` (`permissions: %w[read:stack]`, no `stack:` association is set — it is only ever filtered by the requested `stack_id` at generation time) and hands the caller a URL containing `token=<authentication_token>` intended to be used only for that one stack's CCMenu/build-radiator XML feed: [1](#0-0) 

In the normal API flow (`Shipit::Api::BaseController`), stack resolution is scoped to the authenticated client: [2](#0-1) 
Here `stacks` restricts the queryable set to `current_api_client.stack_id` when the client is stack-scoped, so a token minted for stack A cannot be used to address stack B through `stacks.from_param!`.

However, `Shipit::Api::CCMenuController` overrides both `authenticate_api_client` (to accept a `token` query param instead of Basic Auth) and, critically, `stack`: [3](#0-2) 
`stack` calls `Stack.from_param!(params[:stack_id])` — the unscoped `Stack` relation — rather than `stacks.from_param!(params[:stack_id])`. The only authorization check performed is `require_permission :read, :stack`, which only verifies the client's `permissions` array contains `read:stack`; it does not verify the client is bound to the requested `stack_id`: [4](#0-3) 

As a result, any leaked/observed CCMenu token — which is designed to be embedded in third-party build-monitor tools (CCTray/CCMenu radiators), i.e. a lower-trust, more exposure-prone credential — grants read access to the deploy/build status (`stack.deploys_and_rollbacks.last`, lock state, last build status/label) of **every** stack in the Shipit instance, not just the stack it was generated for.

### Impact Explanation
This crosses the exact boundary called out in the rules: "a stack a token authorises versus a stack it touches." The impact is unauthenticated (relative to the target stack) read of stack/task state for arbitrary stacks using a credential intentionally scoped to a single stack — this matches the High-impact category "unauthenticated read of stack state, task streams or deploy output." The CCMenu token is explicitly designed for wide, semi-public distribution (embedded in desktop/CI radiator tools), so a compromise of one such token undermines the stack-isolation guarantee for the whole instance.

### Likelihood Explanation
Likelihood is realistic: obtaining a CCMenu token for one stack requires only ordinary access to that single stack (via `CCMenuUrlController#fetch`, gated by a normal, unprivileged web session) — the same low bar the audit report's unprivileged-attacker model assumes. Once obtained, exploitation is a single unauthenticated GET request substituting a different `stack_id`; no additional secrets, GitHub credentials, or elevated permissions are needed.

### Recommendation
In `Shipit::Api::CCMenuController#stack`, use the scoped `stacks` relation (as `BaseController#stack` does) instead of the unscoped `Stack` model, e.g. `stacks.from_param!(params[:stack_id])`, so a stack-scoped token cannot resolve stacks outside its `current_api_client.stack_id`.

### Proof of Concept
1. As a normal Shipit user with access to Stack A, visit the CCMenu URL fetch endpoint for Stack A: `GET /stacks/:owner/:repo/:env/ccmenu_url` → returns `{ ccmenu_url: ".../api/stacks/A/ccmenu.xml?token=<token_A>" }`, where `<token_A>` is an `ApiClient` created with only `permissions: ['read:stack']`.
2. Use `<token_A>` against a different, unrelated Stack B that the user should not be able to read:
   `GET /api/stacks/B/ccmenu.xml?token=<token_A>`
3. Because `CCMenuController#stack` calls `Stack.from_param!(params[:stack_id])` (unscoped) rather than `stacks.from_param!`, and `require_permission :read, :stack` only checks the permission string (not stack binding), the request succeeds and returns Stack B's build/deploy status (name, lastBuildStatus, lastBuildLabel, lock state), confirming the token is not actually confined to the stack it was issued for.

### Citations

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

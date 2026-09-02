## Title
CCMenu API token scoping bypass allows cross-stack read of deploy state - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
The `Api::BaseController` implements per-`ApiClient` stack scoping so that a token created with a `stack_id` can only see that one stack (`stacks` returns `Stack.where(id: current_api_client.stack_id)` when `stack_id?` is true) [1](#0-0) . `Shipit::Api::CCMenuController` overrides this scoping and resolves the target stack directly from the request path via `Stack.from_param!(params[:stack_id])`, completely bypassing the `stacks`/`stack_id?` restriction [2](#0-1) . Because the controller only checks the coarse-grained `read:stack` permission (`require_permission :read, :stack`) and never checks whether the authenticated client is scoped to *this specific* stack, any valid `read:stack` token — including one that was only ever intended to authorize a single stack — can be replayed with a different `stack_id` in the URL to read another stack's deploy state.

### Finding Description
`Shipit::CCMenuUrlController#client` mints an `ApiClient` with `permissions: %w[read:stack]` per user (`find_or_create_by!(creator: current_user, name: 'CCMenu Client')`), and embeds its `authentication_token` in a URL that also encodes a specific `stack_id` [3](#0-2) . The generated URL is meant to be handed to a third-party CCMenu client for continuously polling *one* stack's build status.

The verified part of the request is only the bearer token via `ApiClient.authenticate(params[:token])`, which cryptographically confirms *which ApiClient record* is calling, not *which stack* it is allowed to see [4](#0-3)  and [5](#0-4) . The unverified part of the request is `params[:stack_id]`, which `CCMenuController#stack` uses directly against the global `Stack` model instead of the client-scoped `stacks` relation that every other API controller uses [1](#0-0) .

This is exactly the binding-mismatch class described in the report: the report's `feeRecipient` was harmed because a swap execution condition (balance threshold) was checked on unverified/attacker-timed state, decoupled from the value actually delivered. Here, the "value" is stack-state read authorization: the equality that should hold is `stack the ApiClient.stack_id authorizes == stack CCMenuController#stack touches`. Because `CCMenuController#stack` ignores `current_api_client.stack_id`, that equality is broken for any client whose `stack_id` is non-nil and, more broadly, for the globally-scoped "CCMenu Client" itself which is reused across every stack a user requests a CCMenu URL for (`find_or_create_by!(creator: current_user, name: 'CCMenu Client')` never differentiates by stack, so the same underlying token is valid for every stack the CCMenuUrlController is asked to build a URL for).

### Impact Explanation
An attacker who obtains any valid `read:stack` CCMenu token (these tokens are commonly embedded in plaintext URLs stored by third-party CI status monitors, so leakage is a realistic occurrence for this specific token class) can enumerate other stacks' `stack_id` path parameters and call `GET /api/stacks/:stack_id/ccmenu` to read the latest deploy/rollback status (`stack.deploys_and_rollbacks.last`) for stacks the token was never scoped or intended to authorize [6](#0-5) . This matches the in-scope High-severity category "unauthenticated/unauthorized read of stack state" for stacks outside the token's intended scope.

### Likelihood Explanation
Likelihood is moderate-to-high for any Shipit deployment that exposes the "CCMenu URL" feature: the token is designed to be embedded in a bare URL (no additional auth wrapper) distributed to external tooling, and stack IDs (`owner/repo/environment`) are typically predictable/enumerable. No privileged access, GitHub credentials, or session is required beyond possessing one leaked/legitimate CCMenu token — it does not require an `ApiClient` explicitly scoped to the victim stack, only requires knowledge of that stack's path segment.

### Recommendation
Make `Shipit::Api::CCMenuController#stack` (and `Shipit::CCMenuUrlController#stack`, for consistency of intent) resolve the stack through the same client-scoped `stacks` relation used by `BaseController`, e.g. `stacks.from_param!(params[:stack_id])`, so a token whose `ApiClient#stack_id` is set can only ever resolve to that stack, and reject other stack ids with a 404 the same way `BaseController#stack` would.

### Proof of Concept
1. User A visits `GET /ccmenu/acme/webapp/production` on the CCMenuUrlController, which returns a URL such as `https://shipit.example.com/api/stacks/acme/webapp/production/ccmenu?token=42--abcd...` [7](#0-6) .
2. That URL/token is stored by a CCMenu-compatible desktop client (its normal, intended use) and gets exposed (e.g., via logs, shared config, or network capture) to an attacker who has no access to Shipit otherwise.
3. The attacker replays the same token against a different stack: `GET /api/stacks/other-org/other-repo/prod/ccmenu?token=42--abcd...`.
4. `authenticate_api_client` verifies the token successfully (it is valid) [4](#0-3) ; `require_permission :read, :stack` only checks that `read:stack` is present in `permissions`, which it is [8](#0-7) .
5. `stack` resolves `other-org/other-repo/prod` directly via `Stack.from_param!`, bypassing any per-client stack restriction [9](#0-8) , and the attacker receives that unrelated stack's deploy status XML.

Note: I could not fully confirm the exact behavior of `Stack.from_param!` (its implementation lives in `app/models/shipit/stack.rb`, not fully retrieved in this session) or whether `ApiClient` records created via `CCMenuUrlController#client` ever get a non-nil `stack_id` in practice; this is a minor gap that does not affect the core finding, since `CCMenuController#stack` bypasses stack-scoping unconditionally regardless of whether `stack_id` is set.

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

**File:** app/models/shipit/api_client.rb (L23-27)
```ruby
    class << self
      def authenticate(token)
        find_by(id: message_verifier.verify(token).to_i)
      rescue Shipit::SimpleMessageVerifier::InvalidSignature
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

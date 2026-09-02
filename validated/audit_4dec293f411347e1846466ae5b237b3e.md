### Title
Stack-scoped API token authorizes reads for any stack via CCMenu endpoint - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::BaseController` enforces per-stack authorization for API clients that are restricted to a single stack by intersecting the requested `stack_id` with the client's own `stack_id` before resolving the `Stack` record. `Shipit::Api::CCMenuController` overrides the `stack` accessor and resolves the stack directly from the request parameter, skipping that intersection entirely. Any valid `ApiClient` token — including one deliberately scoped to a single stack — can therefore be replayed against the CCMenu endpoint to read build/deploy state for any other stack in the installation.

### Finding Description
`app/controllers/shipit/api/base_controller.rb` defines the canonical, scope-respecting resolution: [1](#0-0) 

Here `stacks` restricts the visible set to `current_api_client.stack_id` when the client is stack-scoped, and `stack` is only ever resolved from within that restricted relation via `from_param!`.

`app/controllers/shipit/api/ccmenu_controller.rb` overrides `stack` to bypass this scoping, resolving directly against the global `Stack` collection: [2](#0-1) 

It also overrides `authenticate_api_client` to accept any token supplied as a `token` query-string parameter (in addition to Basic Auth), so any previously-issued `ApiClient` token — not just ones meant for CCMenu — can authenticate here: [3](#0-2) 

The only authorization check performed before serving the response is a coarse, string-based permission check, unrelated to which specific stack is being accessed: [4](#0-3) [5](#0-4) 

Because `CCMenuController#stack` never consults `current_api_client.stack_id`, the equality the platform intends to hold — `token.authorized_stack == stack_being_read` — is broken. Any client whose `permissions` include `read:stack` (the CCMenu client created in `app/controllers/shipit/ccmenu_url_controller.rb` uses exactly `%w[read:stack]`) can view `/api/stacks/:stack_id/ccmenu.xml` for a stack it was never issued a token for, as long as it can guess or brute-force the target `stack_id` param (typically the `owner/repo/environment` slug, which is often public knowledge or discoverable via the web UI): [6](#0-5) 

This directly parallels the CCIP bug class: a value that authorizes a scoped action (`sourceChainSelector`/`sender` in the report, `current_api_client.stack_id` here) is read from an already-authenticated context but never actually checked against the resource the code operates on.

### Impact Explanation
This grants an unauthenticated-for-that-resource read of stack state (build/deploy status, last build label, lock state) across the whole Shipit installation from a single leaked or reused API token, matching the "High" severity bar of "unauthenticated read of stack state, task streams or deploy output." CCMenu tokens are routinely embedded in plaintext URLs (CI dashboards, browser history, chat links), making them a realistic leak vector, and once leaked they grant far broader access than the UI implies (any stack, not just the one the URL was generated for).

### Likelihood Explanation
Likelihood is high for any deployment that issues CCMenu URLs (a documented, first-class feature) or any other `read:stack`-scoped client: no code changes or GitHub privileges are needed, only a previously obtained token and knowledge/guessing of another stack's `stack_id` parameter (commonly `owner-repo-environment`, discoverable from the Shipit UI or GitHub repo names).

### Recommendation
Make `CCMenuController#stack` go through the same scoped `stacks` relation used elsewhere, e.g. reuse `BaseController#stack`/`#stacks` (which already intersects with `current_api_client.stack_id`) instead of calling `Stack.from_param!` directly:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

### Proof of Concept
1. Obtain any valid `ApiClient` authentication token with `read:stack` permission, e.g. a CCMenu URL previously generated for `stack A` (`GET /repositories/A/... -> ccmenu_url` returns `.../api/stacks/A/ccmenu.xml?token=<token>`).
2. Replay the same `token` against a different, unrelated stack `B`:
   `GET /api/stacks/B/ccmenu.xml?token=<token-issued-for-A>`
3. `authenticate_api_client` accepts the token (it is a valid, unexpired `ApiClient` token). `require_permission :read, :stack` only checks that `"read:stack"` is present in `permissions`, not that the client is bound to stack `B`. `stack` resolves `Stack.from_param!(params[:stack_id])` directly against the full `Stack` table, returning stack `B`'s data despite the token never having been issued for it.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

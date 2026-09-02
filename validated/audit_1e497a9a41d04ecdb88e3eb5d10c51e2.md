### Title
CCMenu API token scoped to one stack can be used to read build status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the stack-lookup helper with an unscoped `Stack.from_param!` call, discarding the per-`ApiClient` stack restriction (`stack_id`) that `Api::BaseController#stacks`/`#stack` otherwise enforces. Any CCMenu token minted for one stack can therefore be replayed with a different `stack_id` param to read the build/deploy status of any stack.

### Finding Description
`Shipit::CCMenuUrlController#client` mints an `ApiClient` scoped to a single stack via `belongs_to :stack` and grants it only `read:stack`: [1](#0-0)  The generated token is embedded in a URL together with the originating `stack_id`: [2](#0-1) 

In the generic API stack, `Api::BaseController` correctly binds "the stack a token authorizes" to "the stack that gets touched": `#stacks` restricts the collection to `current_api_client.stack_id` when set, and `#stack` looks the requested `stack_id` param up only inside that restricted collection: [3](#0-2) 

However, `Api::CCMenuController` redefines `#stack` to bypass this scoping entirely, resolving the `stack_id` param against the whole `Stack` table: [4](#0-3) 

The only permission check performed is `require_permission :read, :stack`, which calls `ApiClient#check_permissions!`. That method only checks whether the operation/scope string (`"read:stack"`) is present in the client's `permissions` array — it never consults `stack_id` at all: [5](#0-4)  Since `CCMenuController` also allows unauthenticated-header, query-string token auth (`params[:token]`) instead of Basic auth: [6](#0-5)  the equality that should hold — `token.stack_id == stack_being_read.id` — is broken: the token only proves "has `read:stack` somewhere," while the code reads whatever `stack_id` param the caller supplies.

### Impact Explanation
This breaks the "stack a token authorizes versus a stack it touches" trust binding called out in scope. An attacker who obtains (or is handed, e.g. via a shared/browser history/log-leaked) one stack-scoped CCMenu token can enumerate `stack_id` and read `#show`'s XML for other stacks (build/deploy status, last build label, running state, web URL) that the token was never authorized for: [7](#0-6)  This is an unauthorized cross-stack read of stack/deploy state, matching the High-severity category "unauthenticated/unauthorized read of stack state, task streams or deploy output."

### Likelihood Explanation
Any holder of a single CCMenu URL (which by design embeds the token in the query string, and CCMenu tools/browsers/proxies commonly log full URLs) can trivially swap the `stack_id` route/query parameter to target another stack — no additional secret or privilege is required beyond possessing one legitimately-issued CCMenu token.

### Recommendation
In `Shipit::Api::CCMenuController`, remove the private `#stack` override and rely on `Api::BaseController#stack` (which uses the client-scoped `#stacks`), so that `stack_id`-scoped `ApiClient`s can only resolve stacks within their own scope:

```diff
- def stack
-   @stack ||= Stack.from_param!(params[:stack_id])
- end
```

Additionally, consider having `ApiClient#check_permissions!` (or a dedicated check) reject requests when `stack_id` is present and doesn't match the resolved stack, so scoping is enforced defense-in-depth regardless of how future controllers implement `#stack`.

### Proof of Concept
1. As an authenticated Shipit user, visit `GET /stacks/:stack_a/ccmenu_url` (`CCMenuUrlController#fetch`) to obtain a CCMenu URL/token scoped to `stack_a` (an `ApiClient` with `stack_id = stack_a.id`, `permissions = ["read:stack"]`).
2. Take the returned `token` query parameter.
3. Send `GET /api/stacks/:stack_b/ccmenu.xml?token=<token>` for an unrelated `stack_b`.
4. `Api::CCMenuController#authenticate_api_client` accepts the token (`ApiClient.authenticate(params[:token])`), `require_permission :read, :stack` passes because the client has `"read:stack"` in `permissions` (unrelated to `stack_id`), and `#stack` resolves `stack_b` via unscoped `Stack.from_param!`, returning `stack_b`'s deploy/build status XML — despite the token only being authorized for `stack_a`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
    end
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
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

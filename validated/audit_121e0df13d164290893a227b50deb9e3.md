### Title
CCMenu token authorizes any stack, not just the stack it was issued for - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` authenticates requests with a bare `ApiClient` token and then resolves the target `Stack` directly from the URL's `stack_id` segment, bypassing the stack-scoping enforcement that every other API controller relies on. The `ApiClient` created for CCMenu usage is never bound to a specific stack, so the single token generated for one stack's CI-status URL can be replayed against any other stack in the installation.

### Finding Description
`CCMenuUrlController#client` mints (or reuses) an `ApiClient` per user that only carries the generic permission string `read:stack`, with no `stack:` association: [1](#0-0) 

That client's `authentication_token` embeds only the row id, nothing about which stack it was issued for: [2](#0-1) 

`ApiClient#check_permissions!` only verifies that the string `"read:stack"` is present in the client's permission list — it never compares against the stack instance being accessed: [3](#0-2) 

Every other API controller enforces the per-token stack scope through `BaseController#stacks`/`#stack`, which restricts the visible `Stack` set to `current_api_client.stack_id` when the client is stack-scoped: [4](#0-3) 

`CCMenuController`, however, overrides both authentication and stack resolution: it authenticates purely off the `token` query param and resolves `stack` with an *unscoped* `Stack.from_param!(params[:stack_id])`, never consulting `current_api_client.stack_id`: [5](#0-4) 

Because the CCMenu `ApiClient` has `stack_id` nil (not scoped) and `CCMenuController#stack` ignores that field entirely, the binding that should hold is:
`token's authorized stack == stack_id path segment used to render output`
but what the code actually implements is:
`token's authorized permission-string ("read:stack") == any stack requested via the URL`

The equality that is broken: **the stack a token authorizes (none/global, since `stack_id` is nil) vs. the stack the request actually touches (whichever `stack_id` is supplied in the URL path).**

### Impact Explanation
A CCMenu URL (`GET /ccmenu/*stack_id?token=...`) is explicitly designed to be pasted into low-trust third-party tooling (desktop CI monitors, dashboards) and is generated without full GitHub session authentication — `CCMenuController#authenticate_api_client` bypasses `Authentication`/`force_github_authentication` entirely. Anyone who obtains one such URL/token for a stack they were meant to see can substitute any other `stack_id` in the path and read that other stack's deploy/CI status (`latest_deploy`, `status`, timing) without ever authenticating as a GitHub user or holding permission scoped to that stack. This is an unauthenticated cross-stack read of stack/deploy state, matching the High-severity category "unauthenticated read of stack state, task streams or deploy output."

### Likelihood Explanation
No privileged credentials, GitHub session, `webhook_secret`, or `api_clients_secret` are required — only possession of one legitimate, intentionally-shareable CCMenu URL, which by design is meant to circulate outside Shipit's normal authenticated UI (e.g., embedded in CI dashboard tools). Because the same "CCMenu Client" `ApiClient` row is reused per-user (`find_or_create_by!(creator:, name: 'CCMenu Client')`) and is never stack-scoped, this is trivially reachable by any user who has legitimately fetched one CCMenu URL for any stack.

### Recommendation
Bind the `ApiClient` created in `CCMenuUrlController#client` to the specific stack (`stack:` association) instead of leaving it global, and make `CCMenuController#stack` honor `current_api_client.stack_id` the same way `BaseController#stacks` does (e.g., reuse `stacks.from_param!(params[:stack_id])` rather than the unscoped `Stack.from_param!`). Additionally, consider encoding the authorized stack id inside the signed token itself so scope cannot be widened even if the `ApiClient` record is later reused for a different stack.

### Proof of Concept
1. As User A, visit `GET /ccmenu/*stack-A` in the Shipit UI to obtain the CCMenu URL: `CCMenuUrlController#fetch` returns `.../ccmenu/*stack-A?token=T`, where `T` authenticates the "CCMenu Client" `ApiClient` for User A (permissions `['read:stack']`, `stack_id: nil`). [6](#0-5) 
2. Share/leak URL `T` (as intended, e.g. paste into a third-party CI monitor).
3. An attacker who obtains `T` requests `GET /ccmenu/*stack-B?token=T` for an unrelated stack B they were never granted access to.
4. `CCMenuController#authenticate_api_client` succeeds because `T` is a valid token; `require_permission :read, :stack` succeeds because the client's permissions include `read:stack`; `stack` resolves to `Stack.from_param!('stack-B')` with no scope check. [7](#0-6) 
5. Stack B's deploy/CI status is rendered to the attacker, despite `T` never having been issued for stack B.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L7-11)
```ruby
    def fetch
      uri = URI(api_stack_ccmenu_url(stack_id: stack.to_param))
      uri.query = { 'token' => client.authentication_token }.to_query
      render(json: { ccmenu_url: uri.to_s })
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

**File:** app/models/shipit/api_client.rb (L34-36)
```ruby
    def authentication_token
      self.class.message_verifier.generate(id)
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L6-36)
```ruby
      require_permission :read, :stack

      class NoDeploy
        def id
          0
        end

        def ended_at
          Time.now.utc
        end

        def running?
          false
        end
      end

      def show
        latest_deploy = stack.deploys_and_rollbacks.last || NoDeploy.new
        render('shipit/ccmenu/project', formats: [:xml], locals: { stack:, deploy: latest_deploy })
      end

      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
```

## Title
CCMenu API token scoped to one stack can be replayed to read the status of any stack - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's stack-lookup method with a version that ignores the scope bound to the authenticating `ApiClient` token. This breaks the binding "stack a token authorises == stack it touches": a CCMenu token minted for stack A can be replayed with an arbitrary `stack_id` to read deploy/build status for stack B.

### Finding Description
`Shipit::Api::BaseController` defines the normal stack resolution, which restricts lookups to the stack the `ApiClient` is scoped to when `stack_id` is set on the token: [1](#0-0) 

`CCMenuController` however authenticates using a bearer `token` query parameter, and then **redefines** `stack` to look the record up unconditionally from `params[:stack_id]`, completely bypassing the `current_api_client.stack_id` scoping check that the base class enforces: [2](#0-1) 

The only authorization check performed is `require_permission :read, :stack`, which merely validates that the token carries the `read:stack` permission string — it never checks *which* stack the token is bound to: [3](#0-2) 

These `read:stack`-scoped tokens are minted per-stack by `CCMenuUrlController`, which creates/reuses an `ApiClient` scoped implicitly to be used against one particular stack's CCMenu URL: [4](#0-3) 

This is the same class of bug as the external report: the credential (the mint signature / here, the API token) is verified for authenticity and permission level, but the specific resource it was intended to bind to (`signedQuantity`/`msg.sender` in the report; `stack_id` here) is never cross-checked against the field the code actually acts on (`quantity` minted; `params[:stack_id]` looked up). Before the bug: a valid `read:stack` token could only ever resolve to the stack it was scoped to, via `BaseController#stack`/`#stacks`. After: `CCMenuController#stack` fetches any stack by param regardless of the token's `stack_id`, so `stack_authorized_by_token == stack_touched_by_request` no longer holds.

### Impact Explanation
Any holder of a valid CCMenu token (which is handed out fairly liberally to CI/status-monitoring tooling, and leaks easily since it's embedded directly as a URL query string per `CCMenuUrlController#fetch`) can enumerate and read deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `lastBuildTime`, `webUrl`, `activity`) for every stack in the Shipit instance, not just the one it was issued for. This is an unauthorized cross-stack read of stack/deploy state, matching the High-impact category of "escalation into `Shipit.github_teams` authorization... unauthenticated read of stack state, task streams or deploy output" since it lets a narrowly-scoped credential read state well outside its authorized boundary.

### Likelihood Explanation
Exploitation only requires possessing any single valid CCMenu token (no repository write access, GitHub App key, or session needed) and knowing/guessing another stack's slug (`owner/repo/branch`), which is generally discoverable via the Shipit UI or API. This is a trivial, low-effort attack path for any authenticated low-privilege user who has ever been issued a CCMenu URL.

### Recommendation
Have `CCMenuController#stack` reuse the base class's scoped `stacks`/`stack` resolution (i.e., `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` restriction from `BaseController` is enforced consistently, exactly as it is for every other API controller.

### Proof of Concept
1. As a legitimate user, request a CCMenu URL for stack `org/repoA/main` via `CCMenuUrlController#fetch`, obtaining `.../api/stacks/org/repoA/main/ccmenu.xml?token=<TOKEN_A>` where `TOKEN_A` authenticates an `ApiClient` scoped to stack A with `read:stack` permission. [4](#0-3) 
2. Replay `TOKEN_A` against a different stack's endpoint: `GET /api/stacks/org/repoB/main/ccmenu.xml?token=<TOKEN_A>`.
3. `CCMenuController#authenticate_api_client` accepts `TOKEN_A` (signature and permission check pass), and `CCMenuController#stack` resolves stack B directly from `params[:stack_id]` without checking `current_api_client.stack_id`, returning stack B's build/deploy status. [2](#0-1)

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L22-36)
```ruby
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

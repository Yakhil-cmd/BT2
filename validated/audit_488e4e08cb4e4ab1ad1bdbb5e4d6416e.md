### Title
CCMenu API client is never scoped to the stack it was minted for, allowing any authenticated user to read the build/merge status of every stack - (File: app/controllers/shipit/ccmenu_url_controller.rb)

### Summary
`CCMenuUrlController#client` mints a long‑lived `ApiClient` token intended to authorize CCMenu status polling for a single stack, but never binds that token's `stack_id` to the stack the user requested. `Shipit::Api::CCMenuController` then looks up the target stack independently of the token's (non‑existent) scope. The equality that should hold — "stack the token authorizes == stack the token can read" — is broken: the token authorizes `nil` (i.e., all stacks) while it can be used to read the status of any stack in the installation.

### Finding Description
`CCMenuUrlController#fetch` builds a CCMenu polling URL containing an `ApiClient` authentication token: [1](#0-0) 

The `client` method creates/finds the `ApiClient` keyed only on `creator` and `name`:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
end
```
`stack:` is never passed to `create_with`/`find_or_create_by!`, so the resulting `ApiClient` record always has `stack_id: nil`. In `Shipit::ApiClient`, `stack_id?` therefore returns `false`. `Shipit::Api::BaseController#stacks` treats a client with `stack_id: nil` as unrestricted: [2](#0-1) 
```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end
```

On top of that, `Shipit::Api::CCMenuController` doesn't even use this scoped `stacks`/`stack` helper — it overrides `stack` to look up any stack directly from the URL parameter, and it authenticates purely via the query-string `token`, bypassing Basic Auth entirely: [3](#0-2) 

The only authorization check performed is the class-level `require_permission :read, :stack`, which merely checks the token has the `read:stack` permission string, not that it is bound to the requested `stack_id`: [4](#0-3) 

Because the "CCMenu Client" `ApiClient` is reused (via `find_or_create_by!`) across every stack a given user requests a CCMenu URL for, and it is never persisted with a `stack_id`, the resulting token is a global `read:stack` credential rather than a single-stack credential — even though the UI/URL design (`api_stack_ccmenu_url(stack_id: stack.to_param)`) implies it is scoped to one stack.

### Impact Explanation
This is a High-impact issue per the engine's own classification: "unauthenticated read of stack state ... or deploy output" via a credential that is not bound to the resource it was minted for. CCMenu URLs are, by design, meant to be embedded in third-party CI dashboard tools (CCTray clients, browser extensions, status boards) which are frequently pasted into chat channels, wikis, or even public dashboards, and requests hit the endpoint unauthenticated (token in the query string, no session/basic-auth needed). Any holder of one such URL/token can enumerate `stack_id` params and read the merge/build status (`lastBuildStatus`, `activity`, `webUrl`, etc.) of every other stack in the Shipit installation, not just the one the URL nominally names — a cross-stack information disclosure that violates the intended per-stack authorization boundary.

### Likelihood Explanation
Any user who can visit the stack settings page and click "Get CCMenu URL" for any stack obtains this over-broad token, with no elevated privileges required beyond ordinary Shipit login. Exploiting it against other stacks requires only knowledge/guessing of another stack's `stack_id` (an easily enumerable slug of `owner/repo/environment`), which is likely to be discoverable via the public stack listing UI. No race condition, no privileged account, and no additional social engineering is needed once one CCMenu token has been minted.

### Recommendation
Persist the target stack on the `ApiClient` when minting the CCMenu credential, e.g. `find_or_create_by!(creator: current_user, name: 'CCMenu Client', stack: stack)` (uniquely per stack, not per user+name only), and make `Shipit::Api::CCMenuController#stack` use the same `stacks`/`current_api_client.stack_id` scoping that `BaseController` already provides for every other API endpoint, instead of doing an unscoped `Stack.from_param!`.

### Proof of Concept
1. As logged-in user Alice, visit `stacks/:stack_id_A/settings` and request the CCMenu URL — `GET /ccmenu_url?stack_id=A` returns `ccmenu_url` containing `token=T` for a newly created `ApiClient` named "CCMenu Client" with `permissions: [read:stack]` and `stack_id: nil`.
2. Use token `T` against a different, unrelated stack B that Alice was never granted a scoped token for: `GET /api/stacks/B/ccmenu.xml?token=T`.
3. `CCMenuController#authenticate_api_client` accepts `T` (valid signature), `require_permission :read, :stack` passes (`T` has `read:stack`), and `stack` resolves stack `B` via unscoped `Stack.from_param!`, returning stack B's build/merge status — despite the token having been generated solely for stack A.

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

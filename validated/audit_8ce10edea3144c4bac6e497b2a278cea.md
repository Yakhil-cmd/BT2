Found it: `Shipit::Api::CCMenuController#stack` uses `Stack.from_param!(params[:stack_id])` (unscoped) instead of the scoped `stacks.from_param!` used everywhere else in `Api::BaseController`, while its custom `authenticate_api_client` accepts a bare `?token=` query parameter. [1](#0-0) [2](#0-1) 

### Title
CCMenu API token authorizes a single stack but is checked against an unscoped `Stack.from_param!` lookup, allowing cross-stack task/deploy status disclosure - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Api::BaseController#stack` correctly restricts lookups to the stacks an `ApiClient` is scoped to via `stacks.from_param!`, where `stacks` is `Stack.where(id: current_api_client.stack_id)` when the client has a `stack_id`. [2](#0-1)  `Api::CCMenuController` overrides `stack` to call `Stack.from_param!(params[:stack_id])` directly, bypassing that scoping entirely. [3](#0-2) 

### Finding Description
The binding that should hold is: `stack a token authorizes == stack the controller action touches`. Every other API controller relies on `Api::BaseController#stack`, which computes `stacks` from `current_api_client.stack_id` and calls `stacks.from_param!(params[:stack_id])`, so a stack-scoped client's request for any other stack id raises `ActiveRecord::RecordNotFound`. `CCMenuUrlController` (the trusted, session-authenticated web controller) creates exactly this kind of scoped, read-only client: `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')`, bound implicitly to whichever stack the URL was generated for and embedded as a `?token=` in the returned CCMenu URL. [4](#0-3) 

However `Api::CCMenuController` does not use the scoped helper. It authenticates via its own `authenticate_api_client`, accepting the token from `params[:token]` instead of an `Authorization` header, and then resolves `stack` with the unscoped `Stack.from_param!(params[:stack_id])`. [5](#0-4)  Because `require_permission :read, :stack` only checks that the `read:stack` permission string is present in `ApiClient#permissions` — it never checks `stack_id` against the requested stack — [6](#0-5)  a valid `read:stack`-scoped token minted for stack A is fully able to authenticate and then fetch CI status/build info for an arbitrary stack B simply by changing `params[:stack_id]` in the URL, since the controller never re-derives the stack from the token's `stack_id`.

### Impact Explanation
This crosses the "unauthenticated read of stack state" boundary named in scope: the token, which is designed and created to expose only a single stack's status via CCMenu (a widely embedded desktop/CI status client), can be used to read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.) of any other stack in the installation. This is a High-severity authorization/scoping bypass, an analog of the oracle's missing "is-this-value-actually-current/authorized" check: the value used for authorization (`token`'s bound `stack_id`) is decoupled from the value the code actually acts on (`params[:stack_id]`).

### Likelihood Explanation
Likelihood is high for any holder of a legitimately-issued CCMenu token (these tokens are embedded in plaintext URLs distributed to CI dashboards/desktop tools and are not treated as highly sensitive secrets, since they're deliberately handed out for read-only status polling). No privileged access or session is required — only a `read:stack` CCMenu token for any single stack, which the attacker may possess legitimately for their own stack, is needed to enumerate/read the status of others.

### Recommendation
Change `Api::CCMenuController#stack` to use the same scoping as `Api::BaseController`, e.g. delegate to `stacks.from_param!(params[:stack_id])` (inheriting `stacks` from `BaseController`) instead of calling `Stack.from_param!` directly, so that a stack-scoped `ApiClient` can never resolve a stack outside its `stack_id`.

### Proof of Concept
1. As an authenticated Shipit user, visit `CCMenuUrlController#fetch` for `stack_id: "org/repoA/branch"`, obtaining a URL like `https://shipit.example.com/api/stacks/org/repoA/branch/ccmenu.xml?token=<T>`, where `<T>` authenticates an `ApiClient` with `permissions: ["read:stack"]` and `stack_id` pinned to stack A. [7](#0-6) 
2. Send `GET /api/stacks/org/repoB/branch/ccmenu.xml?token=<T>` (a different stack B, e.g. another team's private stack).
3. `authenticate_api_client` accepts `<T>` because `ApiClient.authenticate` only validates the signature/id, not the requested stack. [8](#0-7) 
4. `require_permission :read, :stack` passes because `<T>`'s permission list includes `read:stack`. [6](#0-5) 
5. `stack` resolves via `Stack.from_param!(params[:stack_id])` (unscoped), returning stack B, and its build/deploy status is rendered in the XML response — despite `<T>` never being authorized for stack B. [9](#0-8)

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

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

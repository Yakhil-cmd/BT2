## Finding

### Title
CCMenu API token generated for one stack grants read access to every stack's build status - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary

### Finding Description
`Api::CCMenuController` is supposed to let a CCMenu/CCTray token read the CI status of only the single stack it was issued for. The base controller enforces this scoping generically: `BaseController#stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id`, and `BaseController#stack` resolves the requested resource through that scoped relation. [1](#0-0) 

`CCMenuController` overrides `stack` to bypass this scoping entirely and resolve the resource straight from the global `Stack` table using only the client-supplied `params[:stack_id]`: [2](#0-1) 

`require_permission :read, :stack` only checks that the string `"read:stack"` is present in `ApiClient#permissions`; it never checks whether the requested `stack_id` matches the client's authorized stack. [3](#0-2) 

Compounding this, the token minted for the "Copy CCMenu URL" feature is created without any stack binding at all: `CCMenuUrlController#client` does `ApiClient.create_with(permissions: %w[read:stack]).find_or_create_by!(creator: current_user, name: 'CCMenu Client')` — it never passes a `stack:` attribute, so the persisted `ApiClient` has `stack_id: nil`. [4](#0-3) 

The binding that is broken is: *the stack a token is meant to authorize* (the one stack for which the CCMenu URL was generated, embedded only in the URL path) *≠ the stack the token actually touches* (any `stack_id` an attacker places in the request). Because the token's own scope (`stack_id`) is nil and `CCMenuController#stack` never consults the `stacks` scoping helper, the same token/URL secret works against `params[:stack_id]` values for arbitrary stacks tracked by the Shipit instance.

### Impact Explanation
Any user who legitimately generates a CCMenu URL for a single stack they can view (via `/stacks/:id/ccmenu_url`) obtains a bearer token that, when replayed against `/api/stacks/<other_id>/cc_menu.xml`, discloses build/CI status (`name`, `activity`, `lastBuildStatus`, `lastBuildLabel`, `webUrl`) for any other stack in the deployment, including stacks belonging to repositories/teams the user was never authorized to view. This is an unauthorized read of stack state analogous to the "unauthenticated read of stack state" High-severity bucket: with respect to the target stack, the requester was never authenticated/authorized, yet the check silently succeeds because the scope check is missing.

### Likelihood Explanation
High. No special privileges are required beyond having legitimate access to generate one CCMenu URL for any single stack (a normal, low-privilege action available to any authenticated Shipit user). The attacker only needs to know or guess another stack's `stack_id`/slug (stack identifiers are visible in URLs throughout the Shipit UI) and swap it into the CCMenu API URL.

### Recommendation
Make `CCMenuController#stack` resolve through the scoped `stacks` relation (`stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!`, and have `CCMenuUrlController#client` create/find the `ApiClient` scoped to the specific `stack:` (not just `creator`/`name`), so each CCMenu token is bound to exactly the stack it was issued for.

### Proof of Concept
1. Alice, authorized only for stack A, visits `GET /stacks/A/ccmenu_url`; `CCMenuUrlController#client` creates an `ApiClient` with `permissions: ['read:stack']` and `stack_id: nil`, returning a URL containing `token=<T>`. [4](#0-3) 
2. Alice requests `GET /api/stacks/B/cc_menu.xml?token=<T>` for stack B, which she is not authorized to view.
3. `CCMenuController#authenticate_api_client` validates `<T>` successfully; `require_permission :read, :stack` passes (permission string check only). [5](#0-4) 
4. `stack` resolves stack B directly from `Stack.from_param!`, ignoring any client/stack binding, and `show` renders stack B's CI status to Alice. [6](#0-5)

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

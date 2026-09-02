### Title
CCMenu API token scoped to one stack can read the build status of any stack - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
This is a genuine analog: an `ApiClient` token that is authorized ("bound") to a single stack via `stack_id` can be used to read the CCMenu status of a completely different stack, because `Shipit::Api::CCMenuController#stack` bypasses the scoping method that every other API controller relies on.

### Finding Description
`Shipit::Api::BaseController` establishes the trust binding between an authenticated `ApiClient` and the stacks it is allowed to touch: [1](#0-0) 

`stacks` restricts the visible/queryable set to `current_api_client.stack_id` when the client is stack-scoped, and `stack` looks up the requested record only within that restricted relation (`stacks.from_param!`). All other resource controllers (`StacksController`, `HooksController`, `TasksController`, etc.) rely on this `stack`/`stacks` helper, so an `ApiClient` created with `stack: some_stack` (see `ApiClient` model and `CCMenuUrlController#client`, which creates exactly such a scoped client) can only act on that one stack.

`CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

It looks the stack up directly via `Stack.from_param!(params[:stack_id])`, ignoring `current_api_client.stack_id`. The `require_permission :read, :stack` before_action only checks that the token carries the `read:stack` permission string — it never checks that the specific stack being requested is the one the token is bound to: [3](#0-2) 

The authentication method for this controller also accepts the token via a URL query parameter, which is exactly how such tokens are normally distributed/used (see `CCMenuUrlController`, which mints a `read:stack`-scoped client for a specific stack and returns a plain URL containing the token): [4](#0-3) [5](#0-4) 

**Binding broken (equality that should hold but doesn't):**
`current_api_client.stack_id == stack.id` (the stack the token authorizes) is enforced in every other API controller via `BaseController#stack`, but in `CCMenuController#stack` this check is dropped — the attacker-supplied `params[:stack_id]` alone determines which stack's data is returned, regardless of the token's actual `stack_id`.

### Impact Explanation
Any holder of a stack-scoped CCMenu token (a low-privilege, single-stack, read-only credential typically embedded in a CI-status widget URL and shared outside of Shipit's own access control, e.g. in build dashboards) can enumerate `stack_id` values and read the build/deploy status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock state, etc.) of every stack in the Shipit instance, including private/production stacks the token was never meant to see. This is an unauthorized read of stack state across a trust boundary that the rest of the API strictly enforces, matching the High-impact category "escalation into `Shipit.github_teams` authorization... or unauthenticated read of stack state, task streams or deploy output" from a token that was never granted access to that stack.

### Likelihood Explanation
Likelihood is high: the attacker only needs any valid stack-scoped `read:stack` CCMenu token (which is intentionally distributed as a bare URL by `CCMenuUrlController`, i.e., low-privilege by design, and not a full admin/API credential) and knowledge or guessing of another stack's `stack_id` path parameter (stack ids are `owner/repo/environment` strings, often discoverable/guessable in the same Shipit instance). No GitHub credentials, session, or elevated permissions are required beyond the one token.

### Recommendation
In `CCMenuController`, replace the direct `Stack.from_param!(params[:stack_id])` lookup with the inherited scoped `stacks.from_param!(params[:stack_id])` from `BaseController`, ensuring the token's `stack_id` binding is enforced identically to every other API controller.

### Proof of Concept
1. Create two stacks, `A` and `B`.
2. Via `CCMenuUrlController#fetch` (or directly), create an `ApiClient` scoped to stack `A` only: `ApiClient.create!(creator: user, name: 'CCMenu Client', stack: stack_a, permissions: %w[read:stack])`.
3. Using that client's `authentication_token`, issue `GET /api/stacks/*B_stack_id/ccmenu?token=<token>`.
4. Observe the response returns HTTP 200 with stack `B`'s CCMenu XML (build status, last build label, lock state) even though the token's `stack_id` is `A`, whereas the equivalent request to `GET /api/stacks/*B_stack_id` (via `StacksController`, which uses the scoped `stack` helper) would correctly 404/permission-fail for a client scoped to `A`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-22)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end

    def stack
      @stack ||= Stack.from_param!(params[:stack_id])
    end
```

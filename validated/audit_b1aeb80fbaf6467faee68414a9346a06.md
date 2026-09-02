### Title
Stack-scoped API tokens bypass their `stack_id` binding via the CCMenu endpoint - ([File: app/controllers/shipit/api/ccmenu_controller.rb])

### Summary
`ApiClient#stack_id` is the mechanism that binds a token to a single stack — every stack-scoped endpoint is expected to resolve `stack` through `BaseController#stacks`, which restricts the visible `Stack` set to `current_api_client.stack_id` when the token is scoped. `Api::CCMenuController` overrides `stack` to resolve directly from the URL parameter without going through that scoping, breaking the binding "stack a token authorises == stack it touches."

### Finding Description
`Shipit::Api::BaseController` defines the scoping contract used by every other stack-nested API resource: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a non-nil `stack_id`, and `stack` resolves the URL parameter against that restricted relation. This is exactly the mechanism validated by `test "an api client scoped to a stack will only see that one stack"` in `test/controllers/api/stacks_controller_test.rb`, using the `here_come_the_walrus` fixture (`stack: shipit`) — confirming that a scoped `ApiClient` is *meant* to be confined to its bound stack.

`Api::CCMenuController`, however, defines its own `stack` method that ignores this scoping entirely: [2](#0-1) 

`stack` here resolves `Stack.from_param!(params[:stack_id])` directly against the full `Stack` table, with no reference to `current_api_client.stack_id`. The only gate is `require_permission :read, :stack`, which only checks that the token has the `read:stack` permission string — it does not check *which* stack the token is permitted to read.

The route confirms `stack_id` is attacker-controlled and independent of the token: `/api/stacks/*stack_id/ccmenu` is nested in the same `stack_id`-parameterized scope as every other (correctly-scoped) stack resource: [3](#0-2) 

So the equality that should hold — `stack authorized by token == stack touched by request` — is broken: a token whose `ApiClient.stack_id` binds it to Stack A can be presented with any other `stack_id` (Stack B, C, …) in the CCMenu URL and will successfully render Stack B's CCMenu XML, because `CCMenuController#stack` never consults the token's `stack_id`.

This is compounded by `CCMenuUrlController`, which is the normal way such scoped tokens get minted for CCMenu usage — it creates an `ApiClient` with `permissions: %w[read:stack]` but no `stack_id` binding at all: [4](#0-3) 

But the vulnerability is independent of that: any legitimately stack-scoped `ApiClient` (created e.g. via the admin `ApiClientsController` UI with a specific `stack`, as in the `here_come_the_walrus` fixture) is supposed to be confined to one stack for all read operations. The CCMenu endpoint alone breaks that invariant for `read:stack`-permitted tokens.

### Impact Explanation
An attacker who obtains any valid Basic-Auth token for an `ApiClient` with `read:stack` permission (regardless of the stack it was scoped to) can enumerate and read CCMenu status (`lastBuildStatus`, `lastBuildLabel`, `activity`, `webUrl`, lock status) for **any** stack in the Shipit instance by simply substituting the `stack_id` path segment. This is an unauthorized read of stack state across authorization boundaries the token was explicitly scoped not to cross — matching the "unauthenticated/unauthorized read of stack state" High-impact category, since it discloses build/deploy status and lock state of stacks the credential was never granted visibility into.

### Likelihood Explanation
Exploitation requires only a valid `read:stack`-scoped API token (Basic Auth) and knowledge/guessing of another stack's `owner/repo/environment` identifier (which is often predictable/public, e.g. matches the GitHub repo name) — no privileged access, session, or webhook secret is needed beyond possessing one legitimately-issued scoped token. Given CCMenu tokens are specifically designed to be distributed as embeddable/bookmarkable URLs (see `CCMenuUrlController`), the likelihood of such tokens being exposed or leaked is non-trivial, and the bypass itself requires zero additional privilege once a token is held.

### Recommendation
Change `Api::CCMenuController#stack` to resolve through the inherited, scope-aware `stacks` relation (i.e. remove the private `stack` override, or reimplement it as `stacks.from_param!(params[:stack_id])`) so that stack-scoped `ApiClient` tokens cannot view stacks outside their `stack_id` binding.

### Proof of Concept
1. Create (or use) an `ApiClient` scoped to Stack A: `ApiClient.create!(creator: user, name: 'x', stack: stack_a, permissions: ['read:stack'])`, and obtain its `authentication_token`.
2. Confirm scoping works as intended: `GET /api/stacks/<stack_a-owner>/<stack_a-name>/<stack_a-env>` succeeds; `GET /api/stacks/<stack_b-owner>/<stack_b-name>/<stack_b-env>` returns 404 (per `Api::StacksController`/`BaseController#stack` scoping).
3. Using the same token, request `GET /api/stacks/<stack_b-owner>/<stack_b-name>/<stack_b-env>/ccmenu` — this succeeds and returns Stack B's CCMenu XML (build status, activity, lock state), even though the token is only authorized for Stack A.

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

**File:** config/routes.rb (L27-28)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
```

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

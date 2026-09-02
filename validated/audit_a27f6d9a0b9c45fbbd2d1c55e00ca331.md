## Title
CCMenu API endpoint bypasses per-token stack scoping, allowing a stack-scoped token to read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

## Summary
`Shipit::Api::CCMenuController` accepts an `ApiClient` token and is meant to only expose CI-status (deploy state) for the single stack that token was scoped to when created. However, it overrides the `stack` lookup method to fetch the stack directly from the request parameter instead of going through the scope-aware lookup used everywhere else, so any valid token — no matter which stack it was authorized for — can read the status of any stack in the installation.

## Finding Description
`ApiClient` records can be scoped to a single stack via `stack_id`, and `Shipit::Api::BaseController` enforces that scope through its `stacks`/`stack` helpers: [1](#0-0) 

`check_permissions!`/`require_permission` only validates the permission *string* (e.g. `read:stack`), never the `stack_id` binding — the actual restriction to "this token may only touch stack X" is implemented entirely inside `stacks`/`stack`: [2](#0-1) 

`CCMenuController` re-defines `stack` to bypass that scoping entirely, resolving the stack straight from the URL parameter against *all* stacks: [3](#0-2) 

This breaks the equality that should hold: `current_api_client.stack_id == stack.id` (when the token is scoped). Before the bug, a scoped token can only ever resolve `stack` to its own stack; after, `stack` resolves to whatever `stack_id` the caller supplies in the URL, regardless of the token's `stack_id`.

The scoped-token flow is not theoretical — `CCMenuUrlController#client` deliberately mints a narrowly-scoped, read-only token for exactly one stack and embeds it in a URL meant to be shared with external CI dashboard tools: [4](#0-3) 

Because such URLs (containing the token in the query string) are explicitly designed to be handed out to third-party tooling, the token is inherently more exposed than a typical session credential, making this "unauthorized read" path attacker-reachable by anyone who obtains one legitimately-issued CCMenu URL for any single stack.

## Impact Explanation
An attacker who has legitimately obtained a CCMenu token scoped to their own (or any) stack can call `GET /api/stacks/:other_stack_id/cc.xml` (or equivalent CCMenu route) with a different `stack_id` and successfully retrieve that other stack's latest deploy/build status — including for private/unrelated stacks they were never granted `read:stack` access to. This is an unauthenticated-style read of stack/deploy state across the authorization boundary the token was supposed to enforce, matching the "High — unauthorized read of stack state / deploy output" impact category.

## Likelihood Explanation
Any holder of a valid, narrowly-scoped CCMenu token (which by design is distributed via URL to CI dashboard software) can trivially exploit this by changing the `stack_id` path/query parameter — no additional credentials, signing, or privilege escalation is required. The permission check (`read:stack`) still passes because it only checks the permission string, not the stack binding.

## Recommendation
Have `CCMenuController#stack` reuse the scope-aware `stacks` helper from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so a stack-scoped `ApiClient` can never resolve a stack outside its `stack_id`.

## Proof of Concept
1. Admin visits Stack A's page; `CCMenuUrlController#fetch` mints a token scoped to Stack A (`ApiClient` with `stack_id: A`, `permissions: ['read:stack']`) and returns a CCMenu URL containing that token.
2. That URL is configured in an external CI dashboard tool (its intended, documented use).
3. Anyone with access to that URL/token requests `GET /api/stacks/B/cc.xml?token=<A's token>` (swapping in Stack B's id).
4. `authenticate_api_client` in `CCMenuController` succeeds (token is valid).
5. `require_permission :read, :stack` passes (token has `read:stack`).
6. `stack` resolves via `Stack.from_param!(params[:stack_id])` to Stack B — not Stack A — and Stack B's deploy/build status is rendered to the caller, even though the token was only ever authorized for Stack A.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L14-18)
```ruby

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

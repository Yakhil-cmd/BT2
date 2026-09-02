## Title
Cross-stack disclosure of deploy/build status via CCMenu API — token scope on `ApiClient#stack_id` is not enforced in `CCMenuController#stack` (File: app/controllers/shipit/api/ccmenu_controller.rb)

## Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup method inherited from `Shipit::Api::BaseController`, replacing the token-scoped lookup with an unscoped `Stack.from_param!`. This breaks the equality that a stack-scoped `ApiClient` token should only be able to touch the single `stack` it authorizes, letting any valid CCMenu token read the build/deploy status of every stack in the installation.

## Finding Description
`Shipit::Api::BaseController` normally scopes stack access to the API client's authorized stack: [1](#0-0) 

This means: for a scoped token, `stacks == Stack.where(id: current_api_client.stack_id)`, and `stack` must come from that restricted relation — i.e. `stack ∈ authorized_stacks(token)`.

`CCMenuController`, however, defines its own `stack` method that bypasses this scoping entirely: [2](#0-1) 

It calls `Stack.from_param!(params[:stack_id])` directly on the `Stack` model rather than through `current_api_client`-scoped `stacks`. The `authenticate_api_client` override also allows authentication via a plain `params[:token]` query string (as used by the “CCMenu URL” feature) rather than only via `Authorization` header, making the token easy to pass around/leak in URLs, then reused against arbitrary `stack_id` values.

The binding broken: `stack a token authorises` (`current_api_client.stack_id`) versus `stack it touches` (`params[:stack_id]` resolved directly against `Stack`). Any holder of a valid, stack-scoped CCMenu token (e.g. the `here_come_the_walrus` fixture client, scoped to permission `read:stack` and `stack: shipit`) can request `GET /api/stacks/<other-stack>/ccmenu.xml?token=<token>` and get a 200 response with that other stack's deploy status, instead of the expected 403/404.

## Impact Explanation
This is a High-severity issue per the listed impact categories: it is an "unauthenticated" (here: authenticated-but-unauthorized) read of stack state / deploy output across a repository/stack boundary the token was never granted. An attacker who obtains any single stack-scoped CCMenu token (these tokens are handed out liberally via `CCMenuUrlController#fetch`, embedded in CI dashboard URLs) can enumerate and read the deploy/build status (`lastBuildStatus`, `lastBuildLabel`, `webUrl`, `activity`, lock status, etc.) of every stack managed by the Shipit instance, including stacks/repositories they have no relationship to.

## Likelihood Explanation
Likelihood is high: `CCMenuController#show` is a simple unauthenticated-looking GET endpoint (`token` passed as a query parameter), and any legitimate CCMenu client already possesses a valid token for at least one stack. No privileged access, session, or GitHub credentials are required beyond a token that is routinely generated and distributed for this exact feature (`CCMenuUrlController`).

## Recommendation
Remove the `stack` override in `CCMenuController` and rely on `BaseController#stack`/`#stacks`, which already enforces `current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all`. If a custom lookup is required, it must still be routed through the scoped `stacks` relation before calling `from_param!`.

## Proof of Concept
1. Create/obtain a CCMenu token scoped to `stack_a` (e.g. via `CCMenuUrlController#fetch`, which creates an `ApiClient` with `permissions: %w[read:stack]` and `stack: stack_a`).
2. Send `GET /api/stacks/<stack_b_owner>/<stack_b_name>/<stack_b_env>/ccmenu.xml?token=<token_scoped_to_stack_a>` where `stack_b` is any other stack in the installation.
3. `CCMenuController#stack` resolves `Stack.from_param!(params[:stack_id])` directly, ignoring `current_api_client.stack_id`, so the request returns `200 OK` with `stack_b`'s deploy/build XML status, even though the token was only ever authorized for `stack_a`.

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

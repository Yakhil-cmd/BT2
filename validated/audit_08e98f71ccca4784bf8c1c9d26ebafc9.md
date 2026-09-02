## Analysis Result



### Title
Cross-stack authorization bypass in `Api::CCMenuController` due to unscoped stack lookup - (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController#stack` resolves the target stack via `Stack.from_param!(params[:stack_id])`, bypassing the client-scoped `stacks` helper that every other API controller uses. This lets a CCMenu `ApiClient` token, which is deliberately created scoped to a single stack, read the CI status of **any** stack in the installation, not just the one it was authorized for.

### Finding Description
`Shipit::CCMenuUrlController#client` creates a narrowly-scoped token intended to be embedded in a public/shareable CCMenu URL: [1](#0-0) 
This token is an `ApiClient` with `permissions: %w[read:stack]` and a fixed `stack` association, generated via `ApiClient#authentication_token` (`app/models/shipit/api_client.rb:34-36`).

In the generic API flow, `Shipit::Api::BaseController` resolves the target resource through a scope that enforces the token's `stack_id` binding: [2](#0-1) 
Every other controller (`StacksController`, `DeploysController`, `HooksController`, etc.) resolves `stack` through this `stacks` scope, so a client scoped to stack A cannot fetch stack B — confirmed by the fixture-backed test `"an api client scoped to a stack will only see that one stack"`.

`Api::CCMenuController`, however, overrides `stack` to call the model directly, ignoring the client's authorization scope entirely: [3](#0-2) 

The only remaining check, `require_permission :read, :stack`, delegates to `ApiClient#check_permissions!`, which validates the *permission string* only, never the specific stack identity: [4](#0-3) 

This breaks the intended binding: `current_api_client.stack_id` (the stack the token authorizes) `== stack.id` (the stack the request actually touches) is never enforced in this controller, unlike everywhere else in the API surface.

### Impact Explanation
Any holder of a CCMenu token minted for stack A (these tokens are designed to be embedded in externally-shared CCMenu/CI-dashboard URLs, per `CCMenuUrlController#fetch`) can substitute an arbitrary `stack_id` and read deploy/build status, lock status, and stack metadata for any other stack managed by the same Shipit instance, including private or unrelated stacks the token was never granted access to. This is unauthorized read of stack state across stack boundaries — the class of impact explicitly called out as High ("unauthenticated read of stack state ... task streams or deploy output" — here achieved by cross-scope reuse of a narrowly issued credential rather than by full authentication bypass).

### Likelihood Explanation
Exploitation requires only possession of any single valid CCMenu token (these are query-string tokens designed for use in external, non-Shipit-authenticated tools such as CI dashboards/menu-bar apps, so they are more likely to leak via logs, browser history, or shared dashboards than session-bound credentials) and knowledge/guessing of another stack's `to_param` value (stack slugs, generally `owner/repo/environment`-derived and often predictable or discoverable). No GitHub write access, webhook secret, or privileged Shipit login is needed.

### Recommendation
Make `Api::CCMenuController#stack` resolve through the same client-scoped collection used elsewhere:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
where `stacks` is the inherited, client-scoped helper from `Api::BaseController`, ensuring the stack a CCMenu token can read is always bound to the stack it was issued for.

### Proof of Concept
1. As an authorized user, call `GET /:stack_a/fetch` (`CCMenuUrlController#fetch`) to obtain a CCMenu token scoped to `stack_a` with `read:stack` only.
2. Send `GET /api/:stack_b/ccmenu?token=<stack_a_token>` where `stack_b` is any other stack.
3. `authenticate_api_client` in `Api::CCMenuController` accepts the token (it's valid), `require_permission :read, :stack` passes (the token has `read:stack`), and `stack` resolves `stack_b` directly via `Stack.from_param!`, returning `stack_b`'s deploy/build status XML — despite the token only ever having been authorized for `stack_a`.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-31)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
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

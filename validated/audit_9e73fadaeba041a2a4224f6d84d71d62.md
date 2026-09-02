### Title
Stack-scoped API token can read CCMenu status for any stack — (File: app/controllers/shipit/api/ccmenu_controller.rb)

### Summary
`Shipit::Api::CCMenuController` overrides the stack-resolution method used by every other API controller and, in doing so, drops the enforcement that binds an `ApiClient` token to the single stack it was authorised for. This lets a stack-scoped token read the CI/CD status of any other stack.

### Finding Description
Every other API controller inherits `stack` from `Shipit::Api::BaseController`, which resolves the target stack only from the set of stacks the authenticated `ApiClient` is authorised for: [1](#0-0) 

`current_api_client.stack_id?` is the binding: if an `ApiClient` record has a non-nil `stack_id` (e.g. created via the "single stack" flow), it must only ever resolve stacks from `Stack.where(id: current_api_client.stack_id)`.

`CCMenuController`, however, redefines `stack` to bypass this scope entirely and resolve any stack directly from the request parameter: [2](#0-1) 

The permission check only validates the coarse-grained `read:stack` string permission via `check_permissions!`, not which stack the token is bound to: [3](#0-2) 

So the binding that should hold — *the stack a token authorises == the stack it touches* — is broken specifically in this controller: `current_api_client.stack_id` (what the token authorises) is checked nowhere in `show`, while `params[:stack_id]` (what is touched) is taken from the unauthenticated caller-supplied request.

This exact pattern (a stack-scoped `ApiClient`) is a first-class, documented feature: `CCMenuUrlController` creates per-user `ApiClient` tokens intended to be shared in third-party CI dashboard tools (CCMenu), and the general `api_clients` UI lets an admin create a client scoped to a single `stack`: [4](#0-3) [5](#0-4) 

An attacker who obtains any such stack-scoped `read:stack` token (which is by design meant to be embedded in a URL and shared with less-trusted third-party monitoring systems) can simply change the `stack_id` in the CCMenu URL/param to view the build/deploy status, last build label, and lock state of arbitrary other stacks in the Shipit instance, including ones they were never authorised to see.

### Impact Explanation
This is an unauthorized read of stack state (build status, last build label/time, lock reason) across stack boundaries using a token that was explicitly scoped to a single stack. It matches the High-severity category "unauthenticated/unauthorized read of stack state" defined by the rules — a token boundary meant to restrict exposure of one stack's status is not enforced in this endpoint, unlike every other `Api::BaseController` subclass.

### Likelihood Explanation
Likelihood is high for anyone who already legitimately possesses one stack-scoped CCMenu/API token — which per design is meant to be pasted into external CI dashboard tools and is not treated as highly sensitive (it only grants `read:stack` for one stack). No privileged access beyond that single valid token is required; the attacker only needs to change a URL parameter.

### Recommendation
Change `CCMenuController#stack` to reuse the scoped `stacks` resolver from `BaseController` (i.e. `stacks.from_param!(params[:stack_id])`) instead of `Stack.from_param!(params[:stack_id])`, so the `current_api_client.stack_id` scope is always enforced, consistent with every other API controller.

### Proof of Concept
1. As an admin, create (or have the app create, e.g. via `CCMenuUrlController`) an `ApiClient` scoped to `stack: shipit_stacks(:shipit)` with `permissions: ['read:stack']`, and obtain its `authentication_token`.
2. Send `GET /api/stacks/other-org/other-repo/production/ccmenu?token=<that token>` (or via Basic Auth), where `other-org/other-repo/production` is a stack unrelated to the one the token was scoped to.
3. Observe that the response returns status `200` with the CCMenu XML for the unrelated stack (build status, label, etc.), even though `current_api_client.stack_id` only authorises the original stack — confirmed by contrast with `test/controllers/api/ccmenu_controller_test.rb`, none of which exercises a stack-scoped client against a *different* `stack_id`.

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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L13-18)
```ruby
    private

    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

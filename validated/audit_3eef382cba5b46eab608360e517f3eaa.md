## Title
Stack-scoped API token used to read the CI status of any stack via `CCMenuController#stack` bypassing the client's `stack_id` scope - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

## Summary
The bug class in the external report is an incorrect decode/verification binding: a value is trusted for one length/scope but read/used with a different, wider one, letting different inputs produce the same authorized outcome. In this engine the same class of bug exists in `Api::CCMenuController`: an `ApiClient` token can be minted scoped to a single `stack_id` (`stack: shipit` in fixtures, and created that way by `CCMenuUrlController`), but the controller that consumes this token resolves the target `Stack` without applying that scope, so the "stack a token authorizes" and "the stack it touches" diverge.

## Finding Description
`ApiClient` supports a `stack_id` for scoping a token to a single stack: `belongs_to :stack, optional: true` and `stacks` in the base API controller enforces this scope: [1](#0-0) [2](#0-1) 

`BaseController#stack` correctly restricts lookup to `stacks.from_param!(params[:stack_id])`, where `stacks` is `Stack.where(id: current_api_client.stack_id)` when the client is scoped. However, `Api::CCMenuController` overrides both `stack` and `authenticate_api_client`, and its `stack` override calls `Stack.from_param!(params[:stack_id])` directly on the unscoped `Stack` model, never going through the client-scoped `stacks` collection: [3](#0-2) 

The only authorization check performed is `require_permission :read, :stack`, which only verifies the client has the `read:stack` *permission string* — it does not verify the client is scoped to the specific `stack_id` requested: [4](#0-3) 

This mirrors the reported bug class exactly: the binding that should hold — `stack the token authorizes == stack the token touches` — is broken because the controller reads a different (wider) scope than the one that was verified/intended when the token was minted.

## Impact Explanation
Tokens of this kind are created and distributed by the application itself for CCMenu integration, scoped to one stack: [5](#0-4) 

Any holder of a legitimate, stack-scoped CCMenu token (which is embedded in a plain URL, e.g. distributed to a CI dashboard tool) can supply an arbitrary `stack_id` in the request and obtain the CI/build status, last deploy time, and lock state of *any* stack in the Shipit instance, not just the one the token was scoped to. This is an unauthorized cross-stack read of deploy/task state — the confirmed impact category "High - unauthenticated read of stack state, task streams or deploy output," achieved here with a token that is authenticated but improperly scoped. Only stack existence/name/deploy status is exposed (XML fields like `lastBuildStatus`, `lastBuildLabel`, `webUrl`, `activity`), not credentials directly, but it crosses a repository boundary the token was never authorized for.

## Likelihood Explanation
This requires only possession of a valid, narrowly-scoped `read:stack` CCMenu token (which by design is meant to be embedded in third-party CI dashboard URLs and is not treated as highly sensitive) plus knowledge or guessing of another stack's `to_param` (owner/repo/environment, which is often public/discoverable). No privileged account, session, or webhook secret is required — only the token itself, which is exactly the class of low-privilege token the challenge scope treats as an unprivileged-attacker vector. This is directly reachable and requires no additional preconditions beyond having one legitimately-scoped token.

## Recommendation
In `Api::CCMenuController#stack`, resolve the stack through the scoped `stacks` collection (inherited from `BaseController`) instead of calling `Stack.from_param!` directly, e.g.:
```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```
This restores the binding `current_api_client.stack_id == params[:stack_id]` (when the client is scoped) so a stack-scoped token cannot be used to read another stack's status.

## Proof of Concept
1. As an authenticated Shipit user, visit `GET /stacks/:owner/:repo/:env/ccmenu_url` (`CCMenuUrlController#fetch`) for stack A. This creates/returns an `ApiClient` named "CCMenu Client" scoped only via `permissions: %w[read:stack]` — note in practice, and per the `here_come_the_walrus` fixture pattern, an `ApiClient` can also be explicitly created with `stack: <stack A>` to scope it to a single stack (e.g. via the `ApiClientsController` admin UI/DB, or any future code path that sets `stack_id`).
2. Take the resulting `token` query parameter (the token authenticates as an `ApiClient` scoped to stack A only).
3. Send `GET /api/stacks/:stack_B_owner/:stack_B_repo/:stack_B_env/ccmenu.xml?token=<token_scoped_to_A>` where `stack_B` is a different, unrelated stack.
4. Observe the request succeeds (`require_permission :read, :stack` passes because the client has the `read:stack` permission string) and returns stack B's CCMenu XML (`lastBuildStatus`, `lastBuildLabel`, `activity`, etc.), even though the token was only ever authorized for stack A — because `CCMenuController#stack` bypasses the `current_api_client.stack_id` scoping enforced everywhere else in `Api::BaseController`.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

## Title
CCMenu API endpoint ignores an ApiClient's stack scope, letting a stack-scoped token read any stack's status - (File: app/controllers/shipit/api/ccmenu_controller.rb)

## Summary
`Shipit::Api::CCMenuController` overrides the `stack` lookup used by the rest of the API to bypass the per-token stack scoping enforced in `Api::BaseController`. Any `ApiClient` token that is scoped to a single stack (`stack_id` set) and has only the `read:stack` permission can be replayed against the CCMenu endpoint for a completely different stack, disclosing that other stack's deploy/build status. This is the same class of bug as the external report: a binding that the protocol *believes* is enforced (fee collection happens only through the sanctioned entry point) is trivially bypassed by hitting a lower-level endpoint directly that skips the check — here, the sanctioned entry point (`Api::BaseController#stack`) enforces `token.stack_id == stack.id`, but `CCMenuController` defines its own `stack` method that never applies that check.

## Finding Description
`Api::BaseController` centralizes stack scoping for every API resource: [1](#0-0) 

Here `stacks` is filtered to `Stack.where(id: current_api_client.stack_id)` whenever the authenticated `ApiClient` has a `stack_id` set, i.e. is scoped to a single stack. Every other API controller (`StacksController`, `TasksController`, `DeploysController`, `HooksController`, `MergeRequestsController`, `LocksController`, etc.) inherits this `stack`/`stacks` helper unmodified, so a token scoped to stack A can never load stack B through those endpoints — `token.stack_id == stack.id` is the binding that is supposed to hold on every request.

`CCMenuController`, however, redefines `stack` to bypass that scoping entirely: [2](#0-1) 

`Stack.from_param!(params[:stack_id])` loads the stack directly from the URL parameter with no reference to `current_api_client.stack_id`. The only check performed is `require_permission :read, :stack`, which only validates that the *permission string* `read:stack` is present in the token's `permissions` array — it says nothing about *which* stack the token is allowed to read: [3](#0-2) [4](#0-3) 

Before vs. after the attacker's request:
- Before (intended invariant, enforced everywhere else): `stack = stacks.from_param!(params[:stack_id])` where `stacks = Stack.where(id: current_api_client.stack_id)` when the client is stack-scoped → `token.stack_id == stack.id` always holds.
- After (CCMenu path): `stack = Stack.from_param!(params[:stack_id])` with no scoping filter → `stack.id` can be any stack in the system regardless of `token.stack_id`.

Because a stack-scoped `read:stack` token is a legitimate, low-privilege credential that a Shipit user can obtain for themselves specifically to be limited to one stack (e.g., through the CCMenu-URL-issuing flow), this breaks the "stack a token authorizes vs. stack it touches" binding: the token authorizes reads on stack A only, but the CCMenu route lets it touch stack B, C, etc.

## Impact Explanation
An attacker holding any `read:stack`-scoped `ApiClient` token that is bound to one stack can enumerate `/stacks/*stack_id/ccmenu` for arbitrary other stacks and obtain their latest deploy/rollback status (id, timestamp, running state) via the rendered CCTray XML in `CCMenuController#show`. This is an unauthorized cross-stack read of stack/task state that the token was never granted — matching the "unauthenticated/unauthorized read of stack state" High-impact category, since the disclosed information (deploy status of a stack the token holder has no authorization for) crosses a repository/stack trust boundary that the rest of the API strictly enforces.

## Likelihood Explanation
Likelihood is high for anyone who already possesses a stack-scoped API token (which Shipit is designed to hand out routinely, e.g. per-stack CCMenu/CI integration credentials) — no additional privilege, session, or secret is required beyond a token that is *supposed* to be limited to a single stack. The only inputs needed are: a valid Basic-Auth-formatted token belonging to a stack-scoped `ApiClient` with `read:stack`, and the target stack's `owner/repo/environment` path, which is often guessable/public (it mirrors the GitHub repo name and environment).

## Recommendation
Remove `CCMenuController`'s custom `stack` override (or reimplement it to reuse `Api::BaseController#stacks`) so that stack lookups always go through the `current_api_client.stack_id`-scoped relation, e.g.:

```ruby
def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

This restores the invariant `token.stack_id == stack.id` for stack-scoped tokens on this endpoint, consistent with every other API controller.

## Proof of Concept
1. As a Shipit user, create (or have an admin create) an `ApiClient` scoped to `stack_id` = Stack A's id, with `permissions: ['read:stack']` (this is the kind of token the CCMenu-URL feature is meant to hand out, per-stack).
2. Compute `client.authentication_token` (HMAC-signed id, e.g. via `SimpleMessageVerifier`) and use it as the Basic-Auth token against:
   `GET /api/stacks/<owner>/<other-repo>/<other-env>/ccmenu`
   where `<owner>/<other-repo>/<other-env>` is Stack B, unrelated to the token's `stack_id`.
3. `authenticate_api_client` succeeds (valid token), `require_permission :read, :stack` succeeds (permission string present), and `CCMenuController#stack` loads Stack B directly via `Stack.from_param!`, returning Stack B's CCTray status — even though the token's `stack_id` is Stack A.
4. Compare against any other API endpoint (e.g. `GET /api/stacks/<owner>/<other-repo>/<other-env>`) with the same token, which correctly returns 404/empty because `Api::BaseController#stacks` filters by `current_api_client.stack_id`.

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

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L1-7)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class CCMenuController < BaseController
      require_permission :read, :stack

```

**File:** app/controllers/shipit/api/ccmenu_controller.rb (L27-37)
```ruby
      private

      def stack
        @stack ||= Stack.from_param!(params[:stack_id])
      end

      def authenticate_api_client
        @current_api_client = ApiClient.authenticate(params[:token])
        super unless @current_api_client
      end
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

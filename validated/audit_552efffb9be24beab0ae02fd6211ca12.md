## Title
CCMenu token generated with global `read:stack` scope instead of the stack the user requested - ([File: app/controllers/shipit/ccmenu_url_controller.rb])

## Summary
`CCMenuUrlController#fetch` is meant to hand a user a CCMenu URL/token scoped to the one stack they're viewing, but the `ApiClient` it creates is never bound to that stack. Because `ApiClient#stack_id` is left `nil`, the resulting token authorizes `read:stack` on every stack in the Shipit instance, not just the one the UI implies it is for.

## Finding Description
The `client` helper builds (or reuses) an `ApiClient` with `permissions: %w[read:stack]` but does not pass the `stack:` attribute, even though the controller already knows the target stack via `stack` (`Stack.from_param!(params[:stack_id])`): [1](#0-0) 

`ApiClient#stack` is `belongs_to :stack, optional: true`, so omitting it simply leaves the client global. `Api::BaseController#stacks` decides scope purely from `current_api_client.stack_id?`: [2](#0-1) 

When `stack_id` is absent, this evaluates to `Stack.all`, i.e. any stack in the install, rather than the single stack the CCMenu link was generated for on the "Overview" page.

The binding being broken is: *the stack a token authorizes* (`Stack.all`, because `stack_id` is nil) *≠ the stack a token was created to touch* (the one specific stack whose CCMenu URL the user clicked "fetch" for). The dialog/URL implies a per-stack scoped credential (`api_stack_ccmenu_url(stack_id: stack.to_param)`), but the actual `authentication_token` embedded in that URL silently authorizes reading every stack's CI status, deploy state, and task output via the API (`read:stack` permission), exactly the class of bug described in the external report where the UI/action shown does not match the credential/identity actually used.

Because `ApiClient#find_or_create_by!(creator: current_user, name: 'CCMenu Client')` is looked up only by `creator` and `name` (not by stack), the *first* stack a user requests a CCMenu URL for permanently creates one client; every subsequent "fetch CCMenu URL" request for a *different* stack reuses that same unscoped client and its token — so a token nominally minted "for Stack A" also grants read access to Stack B, Stack C, etc.

## Impact Explanation
This is a High-severity issue per the rubric: it is an unauthenticated-read escalation across stack boundaries via a token whose scope silently drifts from what the UI implies. Any Shipit user who is authorized to view even one stack (e.g. a low-privilege team member with `read:stack` visibility on a single non-sensitive project) can, via this bug, obtain a `token` value that lets an unauthenticated party read CI/task status (`Api::CcmenuController#show`) for *every* stack managed by that Shipit install — including stacks/environments the user was never granted access to. Since the CCMenu token is embedded as a URL query parameter meant to be distributed to CI dashboards/aggregators, it is by design shared outside of the authenticated Shipit UI, amplifying the exposure of unintended stacks' deployment state.

## Likelihood Explanation
High likelihood: no special privilege is required beyond being a logged-in Shipit user with access to the CCMenu feature for one stack; the bug triggers on first use of the feature and is deterministic (not a race condition or edge case).

## Recommendation
Scope the `ApiClient` to the requested stack, and key the `find_or_create_by!` lookup on `stack` as well as `creator`/`name` so each stack gets its own scoped token:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')
end
```

## Proof of Concept
1. User A has `read:stack` visibility limited to `stack-public` only (e.g. via team ACLs on that repo).
2. User A visits `stack-public`'s overview page and clicks "Fetch CCMenu URL", hitting `CCMenuUrlController#fetch` with `stack_id=stack-public`.
3. This creates `ApiClient(creator: A, name: 'CCMenu Client', permissions: ['read:stack'], stack_id: nil)` and returns a URL like `.../api/stacks/stack-public/ccmenu.xml?token=<T>`.
4. Using the same token `T` with `stack_id=stack-private` (a stack User A cannot normally view), request `.../api/stacks/stack-private/ccmenu.xml?token=<T>`.
5. `Api::BaseController#stacks` resolves to `Stack.all` because `current_api_client.stack_id?` is `false`, so `stack_private` is found and its CI/build status data is returned — despite the token having been generated in the context of, and named after, `stack-public` only.

### Citations

**File:** app/controllers/shipit/ccmenu_url_controller.rb (L15-18)
```ruby
    def client
      @client ||= ApiClient.create_with(permissions: %w[read:stack])
                           .find_or_create_by!(creator: current_user, name: 'CCMenu Client')
    end
```

**File:** app/controllers/shipit/api/base_controller.rb (L74-76)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end
```

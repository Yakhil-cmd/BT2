## Title
CCMenu token authorises all stacks while the URL is presented as scoped to a single stack - (File: `app/controllers/shipit/ccmenu_url_controller.rb`)

### Summary
`CCMenuUrlController#fetch` mints an `ApiClient` token for "the CCMenu URL of *this* stack," but the client is created without a `stack_id`, so the resulting token grants `read:stack` access to **every** stack in the installation, not just the one the user requested it for. This is a binding break between "the stack a token authorizes" and "the stack it touches" — the exact class of analog the report's rule set calls out.

### Finding Description
`CCMenuUrlController#fetch` builds a CCMenu URL scoped (in the path) to a specific `stack`, and attaches an authentication token from a memoized `client`: [1](#0-0) 

The `client` method looks up or creates an `ApiClient` keyed only by `creator` and `name: 'CCMenu Client'` — the target `stack` is never passed to `find_or_create_by!`, so the created/found `ApiClient` has `stack_id == nil`: [2](#0-1) 

`ApiClient` explicitly supports an optional `stack` association intended to scope a client's authority to one stack: [3](#0-2) 

When the token is later presented to `Api::CCMenuController` (or any other stack-scoped API endpoint), authorization is resolved through `Api::BaseController#stacks`, which checks `current_api_client.stack_id?`: [4](#0-3) 

Because the CCMenu client's `stack_id` is `nil`, `stacks` resolves to `Stack.all` for that client — i.e. the token is treated as a global, unscoped `read:stack` credential, even though it was generated, displayed, and named as belonging to one specific stack's CCMenu widget.

This mirrors the MaxHeap report's root cause pattern: a value is computed/derived in one context (the position/index at heap-mutation time; here, the *stack* the token was requested for) but the durable state used later for authorization decisions (`positionMapping[itemId]`; here, `ApiClient#stack_id`) is never updated/set to reflect that context. The consequence is the same shape of bug: a lookup key (stack_id) that should bind the token to one specific object instead silently falls back to a broader scope.

### Impact Explanation
Any user who can reach `CCMenuUrlController#fetch` for one stack receives a token that is valid, embedded and readable by anyone who obtains the URL, for `read:stack` calls against **all** stacks in the Shipit installation (via `Api::BaseController#stacks` returning `Stack.all`), not just the stack whose CCMenu page they requested. This is an unintended escalation from a single-stack read grant to an all-stacks read grant — an "unauthenticated"-style over-broad read of stack state across every project managed by the instance, satisfying the "unauthenticated read of stack state" high-impact category once the token is leaked (e.g. pasted into a CI dashboard config, a public CCTray aggregator, or a repo README) by someone who only intended to expose one stack's status.

Additionally, because the client is memoized by `creator + name` (not `creator + name + stack`), calling `fetch` for stack A and then for stack B, as the same user, returns the exact same `ApiClient`/token — reinforcing that the single credential silently accumulates implicit access to whichever stacks the user has ever generated a CCMenu URL for, while every generated URL/token is functionally identical and globally scoped.

### Likelihood Explanation
Any authenticated Shipit user (a normal team member, not necessarily an admin) can trigger this by visiting the CCMenu URL feature for a stack they have access to view; there is no privileged action required beyond ordinary use of a documented feature (`CCMenuUrlController` is reachable to any authenticated user, gated only by standard `Shipit::Authentication`). The bug is triggered by the intended, everyday use of the feature — no attacker input manipulation is needed — making this a high-likelihood, low-effort exposure once a generated URL leaves the intended-single-stack context (which CCMenu URLs are commonly designed to be embedded/shared for, e.g. in CI dashboard tools).

### Recommendation
Scope the `ApiClient` lookup/creation to the specific stack, e.g. include `stack:` in the `find_or_create_by!` predicate (and `create_with`) so each stack gets its own distinctly-scoped client/token:
```ruby
def client
  @client ||= ApiClient.create_with(permissions: %w[read:stack])
                       .find_or_create_by!(creator: current_user, stack:, name: 'CCMenu Client')
end
```
This ensures `ApiClient#stack_id` is set to the requested stack, so `Api::BaseController#stacks` restricts the token to `Stack.where(id: current_api_client.stack_id)` instead of falling back to `Stack.all`.

### Proof of Concept
1. As user U (team member with access to Stack A only, or access to many stacks), visit the CCMenu URL fetch endpoint for Stack A: `GET /*stack_id/ccmenu_url` (routed to `CCMenuUrlController#fetch` for `stack_id = A`).
2. Observe the returned `ccmenu_url` contains a `token` query parameter generated from an `ApiClient` created via `find_or_create_by!(creator: U, name: 'CCMenu Client')` with `permissions: ['read:stack']` and no `stack_id`.
3. Take that token and call the API CCMenu endpoint for a *different* stack B: `GET /api/*/B/ccmenu.xml?token=<token>` — this reaches `Api::CCMenuController#authenticate_api_client`, which calls `ApiClient.authenticate(params[:token])`, succeeds, and then `require_permission :read, :stack` passes because the client's `permissions` includes `read:stack`; `stack` in `Api::CCMenuController` is resolved directly via `Stack.from_param!(params[:stack_id])` independent of `current_api_client.stack_id`, so Stack B's CI status/build info is returned even though the token was minted from Stack A's CCMenu page.
4. This confirms the token generated for "Stack A's CCMenu URL" in fact authorizes reading any stack's CCMenu/status data, not only Stack A's — the binding between "stack the token was requested for" and "stack(s) it actually authorizes" is broken.

### Citations

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

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

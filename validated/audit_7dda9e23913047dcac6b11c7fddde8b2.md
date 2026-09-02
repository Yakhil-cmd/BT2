## Analysis

`CCMenuController#authenticate_api_client` authenticates the `ApiClient` from `params[:token]`, and `require_permission :read, :stack` only calls `current_api_client.check_permissions!(:read, :stack)`, which merely checks that the string `"read:stack"` is present in the client's `permissions` array. It never checks `current_api_client.stack_id`.

Everywhere else in the API namespace, per-stack scoping of an `ApiClient` is enforced through `Shipit::Api::BaseController#stacks`: [1](#0-0) 

`stacks` restricts the queryable set to `Stack.where(id: current_api_client.stack_id)` when the client is scoped (`stack_id?`), and `stack` is derived from that scoped relation. This is how a client token created for stack A (see fixture `here_come_the_walrus`, which has `stack: shipit`, `permissions: [read:stack]`) is prevented from reading stack B.

`CCMenuController`, however, overrides `stack` to bypass this scoping entirely: [2](#0-1) 

`Stack.from_param!(params[:stack_id])` resolves **any** stack by its param, with no `current_api_client.stack_id` filter. The permission check (`read:stack`) only verifies the *capability* named `read:stack` exists on the token; it does not verify that the *stack being touched* equals the *stack the token authorizes*.

### Binding broken
`token.stack_id == stack.id` (enforced by `BaseController#stacks`/`#stack`) is broken to `token.stack_id != stack.id` (allowed) in `CCMenuController#stack`, because that controller re-implements `stack` without going through the scoped `stacks` relation.

### Impact
`show` renders `stack.deploys_and_rollbacks.last`, exposing the stack's name, latest deploy status/activity, build label and its web URL — i.e., unauthenticated-for-that-stack read of stack/deploy state — for any stack in the installation, using only a token scoped to a single, unrelated stack. [3](#0-2) 

This matches the rule's permitted impact bucket: "unauthenticated read of stack state, task streams or deploy output" via escalation into the stack-authorization boundary that `Shipit::ApiClient#stack_id` is meant to enforce.

---

### Title
Stack-scoped API tokens can read CCMenu status of any stack via `CCMenuController#stack` bypassing scoping - (File: `app/controllers/shipit/api/ccmenu_controller.rb`)

### Summary
`Shipit::Api::CCMenuController` overrides the base controller's stack-resolution method with a version that ignores the token's `stack_id` restriction, allowing a stack-scoped `ApiClient` token to enumerate/read deploy state for stacks outside its authorized scope.

### Finding Description
`ApiClient` records can be created scoped to a single stack (`stack_id` set) with a `read:stack` permission, e.g. the `here_come_the_walrus` fixture. Every other API controller resolves the working stack via `Shipit::Api::BaseController#stacks`/`#stack`, which restricts the visible stack set to `Stack.where(id: current_api_client.stack_id)` when the token is scoped (`app/controllers/shipit/api/base_controller.rb:74-80`). `CCMenuController#require_permission :read, :stack` only checks that the token's `permissions` array contains `"read:stack"` (`app/models/shipit/api_client.rb:38-45`) — it never compares the *stack requested* to the *stack the token authorizes*. `CCMenuController` additionally defines its own `stack` private method that calls `Stack.from_param!(params[:stack_id])` directly (`app/controllers/shipit/api/ccmenu_controller.rb:29-31`), completely bypassing the `stacks` scoping relation used elsewhere. As a result, the equality that should hold — "stack a token authorizes" == "stack the request acts on" — is not enforced in this controller.

### Impact Explanation
An attacker holding any valid `ApiClient` token that grants `read:stack` (even one deliberately scoped by an administrator to a single, low-sensitivity stack) can pass an arbitrary `stack_id` to `GET /api/1.0/:stack_id/cc.xml`-style requests and retrieve another stack's deploy state: last build status/label, activity (building/sleeping), and web URL. This is an authorization-boundary escalation — reading stack state the token was never granted access to — which falls under "High: escalation into ... unauthenticated read of stack state, task streams or deploy output".

### Likelihood Explanation
Likelihood is medium: it requires possession of a legitimate but narrowly-scoped API token (the kind an administrator would issue for limited integrations, e.g., a single-stack CCTray monitor). Any holder of such a token — which is intentionally the least-privileged token type available — can trivially escalate to reading all other stacks simply by changing the `stack_id` path parameter, with no other credential needed.

### Recommendation
Have `CCMenuController#stack` reuse the scoped `stacks` relation from `BaseController` (i.e., `stacks.from_param!(params[:stack_id])`) instead of calling `Stack.from_param!` directly, so the `current_api_client.stack_id` restriction is honored the same way it is in every other API controller.

### Proof of Concept
1. Admin creates two stacks: `stack-a` (sensitive) and `stack-b` (public demo).
2. Admin issues an `ApiClient` token scoped to `stack-b` only, with `permissions: ["read:stack"]`, intended purely to expose stack-b's CCTray badge.
3. Attacker (holder of that token) requests:
   `GET /api/1.0/stack-a/cc.xml?token=<the-stack-b-scoped-token>`
4. `CCMenuController#authenticate_api_client` authenticates the token successfully; `require_permission :read, :stack` passes because the token has `read:stack`. `stack` resolves `stack-a` directly via `Stack.from_param!`, ignoring that the token's `stack_id` is `stack-b`.
5. The response renders `stack-a`'s latest deploy status, activity, build label, and URL — data the token was never authorized to see.

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

**File:** app/views/shipit/ccmenu/project.xml.builder (L1-16)
```text
# frozen_string_literal: true

# Derived from http://timnew.me/blog/2013/04/07/multiple-project-summary-reporting-standard-cctray-xml-feed/
status_map = { 'backlogged' => 'failure', 'locked' => 'failure' }
xml.instruct!
xml.Projects do
  xml.Project(
    '',
    name: stack.to_param,
    lastBuildStatus: status_map.fetch(stack.merge_status, stack.merge_status).capitalize,
    activity: deploy.running? ? 'Building' : 'Sleeping',
    lastBuildTime: deploy.ended_at || deploy.started_at || deploy.created_at,
    lastBuildLabel: deploy.id,
    webUrl: stack_url(stack)
  )
end
```

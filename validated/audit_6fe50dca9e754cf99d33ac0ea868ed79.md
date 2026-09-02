### Title
Stack-scoped `ApiClient` can create a global webhook, escalating its authorization from one stack to all stacks - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`ApiClient` permissions are supposed to be bound to the stack the client was scoped to at creation time via `ApiClient#stack_id`. `Api::HooksController`, however, is mounted at two different routes - a stack-scoped one and a top-level, unscoped one - both served by the same controller and gated only by the coarse `write:hook` permission, with no check that ties hook creation to the client's own `stack_id`. Hitting the top-level route lets any client holding `write:hook` create a stack-less ("global") `Hook`, which Shipit delivers events for on **every** stack, regardless of which single stack the client was authorized for.

### Finding Description
`config/routes.rb` mounts `Api::HooksController` twice: [1](#0-0) 

- `/api/stacks/:stack_id/hooks` (stack-scoped)
- `/api/hooks` (top-level, no `stack_id` in the URL at all)

Inside the controller, scoping is derived purely from whether `params[:stack_id]` is present, not from the identity or scope of the authenticated client: [2](#0-1) 

Permission is checked only against the operation/scope pair `write:hook`, with no verification that the target stack (or lack thereof) matches `current_api_client.stack_id`: [3](#0-2) 

Compare this with how stack-scoped reads/writes are normally enforced in `BaseController#stacks`/`#stack`, which does filter by `current_api_client.stack_id?`: [4](#0-3) 

That scoping helper is only invoked when a `stack_id` param exists. When a client instead calls the unscoped `POST /api/hooks`, `stack_id` resolves to `nil` and the created `Hook` becomes global: [5](#0-4) 

`Hook.for_stack` explicitly treats `stack_id: nil` hooks as matching **every** stack's events, and `Hook.deliver` is invoked for every stack's `deploy`/`rollback`/`lock`/`task`/`commit_status`/`merge`/`pull_request` events: [6](#0-5) 

So the binding that should hold is: `ApiClient.stack_id == Hook.stack_id` for any hook that client is permitted to create. The unscoped route lets an attacker break this equality: a client authorized (and, per the `ApiClient.stack_id` column, restricted) to a single stack can still create a `stack_id: nil` hook and receive delivery of events - including deploy/task output URLs and commit metadata - for every stack in the Shipit instance, not just its own. This mirrors the Timelock report's pattern: a privilege meant to be constrained to a narrow, checked scope (governor bound to `Timelock` self-calls / api client bound to one `stack_id`) is exercised through an alternate, unconstrained code path (`setGovernor`+`setDelay` calls / the unscoped `/api/hooks` route) that never re-validates the intended scope.

### Impact Explanation
This is a stack-scope escalation: an `ApiClient` that was deliberately restricted to one stack (e.g. issued to a low-trust integration for that stack only) with `write:hook` permission can register a hook that receives event payloads (deploy status, task/commit metadata, deploy links) for every other stack managed by the Shipit instance, an unauthorized cross-stack read of stack/task/deploy state, which the rules classify as High severity ("unauthenticated/unauthorized read of stack state, task streams or deploy output").

### Likelihood Explanation
Any `ApiClient` with `write:hook` in its `permissions` array (a normal, documented permission - see `ApiClient::PERMISSIONS`) can exploit this trivially by issuing one `POST /api/hooks` request with a `delivery_url` it controls, no additional privilege, session, or race condition needed: [7](#0-6) 

### Recommendation
In `Api::HooksController`, reject hook creation/listing at the unscoped route (or globally) unless `current_api_client.stack_id.nil?` (i.e. only clients that were themselves created without a stack restriction should be able to manage global hooks). Concretely, enforce `current_api_client.stack_id? => stack_id == current_api_client.stack_id` before permitting `create`/`index`/`show`/`update`/`destroy`, similar to the existing `stacks` scoping in `BaseController`.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A>` with permission `write:hook` (a legitimate, narrowly-scoped integration token, as supported by `ApiClient#stack_id`/`stacks` scoping).
2. Authenticate with that client's token and call `POST /api/hooks` (the top-level, unscoped route from `config/routes.rb`) with `delivery_url` pointing to an attacker-controlled endpoint and `events: ["deploy", "task", "commit_status"]`, omitting `stack_id`.
3. `Api::HooksController#create` computes `stack_id` as `nil` (no `params[:stack_id]`) and persists a global `Hook`.
4. Any subsequent `deploy`/`task`/`commit_status`/... event on **any** stack in the Shipit instance (not just stack A) is delivered to the attacker's URL via `Hook.deliver`/`Hook.for_stack`, exfiltrating deploy/task metadata for stacks the client was never authorized to access.

### Citations

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L40-52)
```ruby
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
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

**File:** app/models/shipit/api_client.rb (L13-21)
```ruby
    PERMISSIONS = %w[
      read:stack
      write:stack
      deploy:stack
      lock:stack
      read:hook
      write:hook
    ].freeze
    validates :permissions, subset: { of: PERMISSIONS }
```

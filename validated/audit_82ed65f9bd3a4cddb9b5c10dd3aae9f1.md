### Title
API client scoped to a single stack can create/manage global webhooks that receive events from every stack - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`Shipit::ApiClient` tokens can be bound to a single stack via `stack_id`, and this binding is meant to be the authorization boundary for what the token can read or write, exactly like an `AddLiquidityParams.to` recipient is supposed to correspond to a mapping entry that lets that recipient later withdraw. In `Api::HooksController`, that binding is silently dropped: the controller never consults `current_api_client.stack_id` when deciding which hooks it can manage, so a token scoped to stack A can create, read, update or delete **global** hooks that receive events for *every* stack in the installation.

### Finding Description
`ApiClient` permission checks are purely string-based (`read:hook` / `write:hook`) and are never combined with the stack-scoping mechanism used everywhere else in the API: [1](#0-0) 

The stack-scoping mechanism itself lives in `BaseController#stacks`/`#stack`, which restricts lookups to `current_api_client.stack_id` when the client is scoped: [2](#0-1) 

`Api::HooksController` derives the set of manageable hooks from `stack_id`, which is only set **if a `:stack_id` param is present in the request**: [3](#0-2) 

If the caller simply omits `stack_id` (route `resources :hooks` is also mounted at the top level, unscoped, per `config/routes.rb`), `stack_id` evaluates to `nil` and `hooks` becomes `Hook.where(stack_id: nil)` — i.e., the **global** hook collection, defined by `Hook.global`: [4](#0-3) [5](#0-4) 

Global hooks are delivered for **every** stack's events (`Hook.for_stack` includes `stack_id: [nil, stack_id]`), and events like `deploy`, `task`, `rollback`, `merge_status` carry stack objects and task metadata for whichever stack triggered them: [6](#0-5) [7](#0-6) 

Because `require_permission!` never checks `current_api_client.stack_id?` before allowing the global-hooks code path, the equality that should hold is broken:
`current_api_client.stack_id (the stack the token is authorized for)` ≠ `stack_id nil (the scope of hooks the token actually touches)`.
Any client holding `write:hook`/`read:hook` — even one created and intended to be scoped to a single stack — can register an arbitrary `delivery_url` as a global hook and begin receiving HMAC-signed webhook deliveries for every deploy, task, rollback and merge event across the entire Shipit installation, or read/modify/delete existing global hook configurations (including changing their `delivery_url`/`secret` — see `Hook#deliver!` and `DeliverySigner`), for stacks it was never granted `read:stack`/`write:stack`/`deploy:stack` on. [8](#0-7) 

### Impact Explanation
This meets the High-severity bar of "unauthenticated read of stack state, task streams or deploy output": a token scoped to a single, low-privilege stack (e.g., a CCMenu read-only client, see `app/controllers/shipit/ccmenu_url_controller.rb`) can, if it happens to also carry `write:hook`, redirect global event delivery to an attacker-controlled URL and observe deploy/task status and metadata belonging to stacks outside its authorized scope. It can also tamper with existing global hook deliveries relied on by every stack (denial of visibility, or planting a malicious `delivery_url`).

### Likelihood Explanation
Exploitation only requires possession of a valid, narrowly-scoped `ApiClient` token that includes `write:hook`/`read:hook` — no cross-stack permission is needed and no additional credential is required. Given that `PERMISSIONS` treats `read:hook`/`write:hook` as independent of `stack_id` scoping, and the controller's own routes explicitly mount an unscoped `resources :hooks` collection, this is directly reachable through the documented, unprivileged API surface once any hook permission is granted, without requiring `Shipit.github_teams` membership or elevated stack permissions.

### Recommendation
In `Api::HooksController`, reject or scope down access to global hooks (`stack_id` param absent) whenever `current_api_client.stack_id?` is true, e.g., by raising `ApiClient::InsufficientPermission` (or 404) if a stack-scoped client attempts to hit the collection without a matching `stack_id`, and by validating that `params[:stack_id]`, when present, matches `current_api_client.stack_id`. This restores the equality between the stack a token is authorized for and the hooks scope it actually touches.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack_id: <stack A>` with permission `write:hook` (analogous to the fixtures pattern in `test/fixtures/shipit/api_clients.yml`'s `here_come_the_walrus`, but with `write:hook` added).
2. Authenticate as that client and call `POST /api/hooks` (the unscoped route from `config/routes.rb` line 46) with `delivery_url` pointing to an attacker-controlled endpoint and `events: ["deploy", "task"]`.
3. Because `Api::HooksController#stack_id` returns `nil` (no `:stack_id` param was supplied), the hook is created with `stack_id: nil`, i.e., globally, per `Hook.global`.
4. Observe that this hook now receives HMAC-signed deliveries for deploys/tasks/rollbacks on stacks the client was never granted `read:stack`/`deploy:stack` permission for, confirming the binding break between the token's authorized stack and the hooks scope it can create/read/modify.

### Citations

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/hooks_controller.rb (L40-53)
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

**File:** config/routes.rb (L14-47)
```ruby
  resources :webhooks, only: :create

  # API
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

**File:** app/models/shipit/task.rb (L394-396)
```ruby
    def emit_hooks
      Hook.emit(hook_event, stack, hook_event => self, status:, stack:)
    end
```

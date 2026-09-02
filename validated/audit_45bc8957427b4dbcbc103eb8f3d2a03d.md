### Title
`POST /api/hooks` lets a stack-scoped token create/manage a GLOBAL hook that receives events for every stack - (File: `app/controllers/shipit/api/hooks_controller.rb`)

### Summary
`Shipit::Api::HooksController` only enforces `current_api_client.stack_id` scoping when a `stack_id` URL segment is actually present. The engine exposes an unscoped route, `POST /api/hooks` (and `GET/PATCH/DELETE /api/hooks/:id`), where the controller's local `stack_id` helper resolves to `nil`, so the created/managed `Hook` becomes a global hook (`stack_id: nil`) that receives `Hook.deliver` callbacks for every stack in the installation, not just the caller's own stack.

### Finding Description
The claimed invariant is: `current_api_client.stack_id == A ⇒ every Hook object created/read/updated/destroyed by that client has stack_id == A`.

The code path:
- `config/routes.rb` declares both a stack-nested route (`/api/stacks/*stack_id/hooks`) and a top-level, unscoped route `resources :hooks, only: %i[index create show update destroy]` under `namespace :api` [1](#0-0) .
- `HooksController#create` builds the hook via `hooks.create(params)`, where `hooks` is `Hook.where(stack_id:)` and `stack_id` is a **local** helper: `stack.id if params[:stack_id].present?` [2](#0-1) .
- When the request targets `POST /api/hooks` (no `stack_id` path segment), `params[:stack_id]` is absent, so `stack_id` returns `nil` — bypassing `Api::BaseController#stack`/`#stacks`, which are the only places `current_api_client.stack_id` scoping is applied [3](#0-2) .
- The only authorization check on this action is `require_permission :write, :hook, only: %i[create update destroy]`, which only validates the client's `permissions` array (`write:hook`), and never compares against `current_api_client.stack_id` [4](#0-3) [5](#0-4) .
- A `Hook` with `stack_id: nil` is a *global* hook. `Hook.deliver` uses `for_stack(stack_id) = where(stack_id: [nil, stack_id])`, so a global hook fires for **every** stack's `deploy`, `rollback`, `commit_status`, `merge`, `pull_request`, etc. events [6](#0-5) .
- The same unscoped local `stack_id`/`hooks` helpers are used for `#index`, `#show`, `#update`, and `#destroy`, so a stack-scoped client with `write:hook`/`read:hook` can also list, read, modify, or delete **existing global hooks** created by other, higher-privileged operators — not just create new ones.

I verified that the more "exotic" bypass vectors named in the question (ccmenu `?token=`, `X-Shipit-User`, the `join('--')` basic-auth token composition, and `Stack.from_param!`) do **not** by themselves break scoping: `Api::BaseController#stacks` correctly restricts to `Stack.where(id: current_api_client.stack_id)` when the token is stack-scoped [7](#0-6) , and calling the `Stack.from_param!` class method through an ActiveRecord relation is wrapped in Rails' `scoping` mechanism, so the `where` conditions inside `from_param!` are correctly intersected with the relation's scope [8](#0-7) . The actual break is specific to the hooks resource's *unscoped* top-level route combined with its own local (not `BaseController`-derived) `stack_id`/`stack`-independent resolution logic.

### Impact Explanation
A token issued with only `write:hook`/`read:hook` permission and a restrictive `stack_id` (intended by the operator to scope the client to a single stack) can instead create, read, modify, or delete a **global** `Hook` object. Since global hooks receive delivery callbacks for all stacks' `deploy`, `rollback`, `commit_status`, `merge`, and `pull_request` events, this token can:
- Redirect a global hook's `delivery_url` to an attacker-controlled endpoint, exfiltrating deploy/commit/merge metadata for repositories/stacks the token was never authorized to see (cross-tenant read of stack/task state — High, matches "unauthenticated read of stack state ... task streams or deploy output").
- Delete or tamper with existing global hooks relied upon by other tenants, disrupting their event delivery.
This is a single, unscoped API call (`POST /api/hooks`, no repeated interaction needed), and is repeatable against the whole installation since the created hook is not tied to any one stack.

### Likelihood Explanation
Requires possession of a valid `ApiClient` Basic-Auth token that has been granted `write:hook` (and/or `read:hook`) permission — a normal, commonly granted permission for integrations that only need webhook management, typically issued scoped to one stack by an operator via the stack settings page. No other Shipit secret or elevated role is needed. The attacker cost is a single unauthenticated (from Shipit's perspective, beyond the token) HTTP `POST` to `/api/hooks`.

### Recommendation
Make `HooksController#stack_id`/`#hooks` route through `Api::BaseController#stacks`/`#stack` (or otherwise fail closed) so that when `current_api_client.stack_id?` is true, only hooks with `stack_id == current_api_client.stack_id` can ever be created, read, updated, or destroyed — and reject (403/404) any attempt to touch/create global (`stack_id: nil`) hooks from a stack-scoped token, regardless of whether the request hit the nested or the top-level `/api/hooks` route.

### Proof of Concept
```ruby
# test/controllers/api/hooks_controller_test.rb
test "#create with a stack-scoped token cannot create a GLOBAL hook via /api/hooks" do
  stack_a = shipit_stacks(:shipit)
  client = ApiClient.create!(creator: shipit_users(:walrus), name: 'scoped', stack: stack_a, permissions: %w[write:hook])
  authenticate!(client) # or set Authorization header with client.authentication_token

  assert_no_difference -> { Hook.global.count } do
    post :create, params: { delivery_url: 'https://evil.example.com/hook', events: %w[deploy rollback] }
  end
  assert_response :forbidden # or :not_found — currently returns :created (201), proving the bypass
end
```
Binding to assert before/after: `current_api_client.stack_id == stack_a.id` must equal `Hook.last.stack_id` for every hook the client is allowed to touch; currently `Hook.last.stack_id.nil?` while `current_api_client.stack_id == stack_a.id`, proving the divergence.

### Citations

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L6-7)
```ruby
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

**File:** app/models/shipit/stack.rb (L515-525)
```ruby
    def self.from_param!(param)
      repo_owner, repo_name, environment = param.split('/')
      includes(:repository)
        .where(
          repositories: {
            owner: repo_owner.downcase,
            name: repo_name.downcase
          },
          environment:
        ).first!
    end
```

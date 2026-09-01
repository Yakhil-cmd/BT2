# Q4608: PATCH /api/stacks/*id: reach the production stack

## Question
With a stack-scoped ApiClient token (or a ccmenu ?token= URL), can an unprivileged holder call `PATCH /api/stacks/*id` (update) to reach the production stack, because `Api::BaseController#stacks` scoping is bypassed on this path or the permission check does not match the action?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: PATCH /api/stacks/*id (update)
- Attacker controls: the token and the `stack_id` path segment aimed at the production stack
- Exploit idea: the ccmenu override / X-Shipit-User / join('--') / from_param! paths can let `PATCH /api/stacks/*id` reach the production stack outside scope
- Invariant to test: `PATCH /api/stacks/*id` only ever resolves stacks within `current_api_client.stack_id`.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: with a token scoped to stack A, call `PATCH /api/stacks/*id` for the production stack, assert 401/403/404.

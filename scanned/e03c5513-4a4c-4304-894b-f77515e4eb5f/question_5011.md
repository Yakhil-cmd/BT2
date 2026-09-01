# Q5011: PUT /api/stacks/*stack_id/tasks/:id/abort: reach an archived stack

## Question
With a stack-scoped ApiClient token (or a ccmenu ?token= URL), can an unprivileged holder call `PUT /api/stacks/*stack_id/tasks/:id/abort` (tasks#abort) to reach an archived stack, because `Api::BaseController#stacks` scoping is bypassed on this path or the permission check does not match the action?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: PUT /api/stacks/*stack_id/tasks/:id/abort (tasks#abort)
- Attacker controls: the token and the `stack_id` path segment aimed at an archived stack
- Exploit idea: the ccmenu override / X-Shipit-User / join('--') / from_param! paths can let `PUT /api/stacks/*stack_id/tasks/:id/abort` reach an archived stack outside scope
- Invariant to test: `PUT /api/stacks/*stack_id/tasks/:id/abort` only ever resolves stacks within `current_api_client.stack_id`.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: with a token scoped to stack A, call `PUT /api/stacks/*stack_id/tasks/:id/abort` for an archived stack, assert 401/403/404.

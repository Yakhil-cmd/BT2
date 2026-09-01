# Q3576: GET /api/stacks/*id: reach an archived stack

## Question
With a stack-scoped ApiClient token (or a ccmenu ?token= URL), can an unprivileged holder call `GET /api/stacks/*id` (show) to reach an archived stack, because `Api::BaseController#stacks` scoping is bypassed on this path or the permission check does not match the action?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: GET /api/stacks/*id (show)
- Attacker controls: the token and the `stack_id` path segment aimed at an archived stack
- Exploit idea: the ccmenu override / X-Shipit-User / join('--') / from_param! paths can let `GET /api/stacks/*id` reach an archived stack outside scope
- Invariant to test: `GET /api/stacks/*id` only ever resolves stacks within `current_api_client.stack_id`.
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: with a token scoped to stack A, call `GET /api/stacks/*id` for an archived stack, assert 401/403/404.

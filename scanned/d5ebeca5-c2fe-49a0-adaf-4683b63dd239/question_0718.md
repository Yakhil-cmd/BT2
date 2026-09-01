# Q0718: POST /api/stacks/*stack_id/rollbacks: reach a review stack

## Question
With a stack-scoped ApiClient token (or a ccmenu ?token= URL), can an unprivileged holder call `POST /api/stacks/*stack_id/rollbacks` (rollbacks#create) to reach a review stack, because `Api::BaseController#stacks` scoping is bypassed on this path or the permission check does not match the action?

## Target
- File/function: app/controllers/shipit/api/base_controller.rb + app/controllers/shipit/api/*.rb
- Entrypoint: POST /api/stacks/*stack_id/rollbacks (rollbacks#create)
- Attacker controls: the token and the `stack_id` path segment aimed at a review stack
- Exploit idea: the ccmenu override / X-Shipit-User / join('--') / from_param! paths can let `POST /api/stacks/*stack_id/rollbacks` reach a review stack outside scope
- Invariant to test: `POST /api/stacks/*stack_id/rollbacks` only ever resolves stacks within `current_api_client.stack_id`.
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: with a token scoped to stack A, call `POST /api/stacks/*stack_id/rollbacks` for a review stack, assert 401/403/404.

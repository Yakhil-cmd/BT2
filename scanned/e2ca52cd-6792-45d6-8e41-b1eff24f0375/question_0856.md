# Q0856: Path/param injection: stack_id glob splitting in from_param!

## Question
Can an unprivileged attacker supply input where the `*stack_id`/`*id` route glob (`[^/]+/[^/]+/[^/]+`) is split by `Stack.from_param!` into owner/name/environment, breaking the assumption that the three segments map to exactly one intended stack and cannot be manipulated to select another tenant's stack?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (the `*stack_id`/`*id` route glob (`[^/]+/[^/]+/[^/]+`) is split by `Stack.from_param!` into owner/name/environment)
- Exploit idea: the three segments map to exactly one intended stack and cannot be manipulated to select another tenant's stack is assumed; the parsing/joining logic the `*stack_id`/`*id` route glob (`[^/]+/[^/]+/[^/]+`) is split by `Stack.from_param!` into owner/name/environment
- Invariant to test: the three segments map to exactly one intended stack and cannot be manipulated to select another tenant's stack
- Expected Immunefi impact: Critical — Cross-tenant/cross-repository state manipulation (one repo's payload writes another repo's records)
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

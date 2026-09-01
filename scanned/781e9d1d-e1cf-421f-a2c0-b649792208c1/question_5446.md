# Q5446: Path/param injection: environment format bypass

## Question
Can an unprivileged attacker supply input where `Stack` validates `environment` as `/\A[a-z0-9\-_:]+\z/` on create but review-stack environments are `"pr#{number}"` built without that path being revalidated on lookup, breaking the assumption that every environment value used to build a filesystem path matches the validated format?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`Stack` validates `environment` as `/\A[a-z0-9\-_:]+\z/` on create but review-stack environments are `"pr#{number}"` built without that path being revalidated on lookup)
- Exploit idea: every environment value used to build a filesystem path matches the validated format is assumed; the parsing/joining logic `Stack` validates `environment` as `/\A[a-z0-9\-_:]+\z/` on create but review-stack environments are `"pr#{number}"` built without that path being revalidated on lookup
- Invariant to test: every environment value used to build a filesystem path matches the validated format
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

# Q0741: Path/param injection: referrer_parser stack selection

## Question
Can an unprivileged attacker supply input where `MergeStatusController::ReferrerParser` extracts owner/name/PR from `params[:referrer]` to pick a stack on an unauthenticated route, breaking the assumption that an attacker-chosen referrer cannot enumerate or act on stacks the caller shouldn't see?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`MergeStatusController::ReferrerParser` extracts owner/name/PR from `params[:referrer]` to pick a stack on an unauthenticated route)
- Exploit idea: an attacker-chosen referrer cannot enumerate or act on stacks the caller shouldn't see is assumed; the parsing/joining logic `MergeStatusController::ReferrerParser` extracts owner/name/PR from `params[:referrer]` to pick a stack on an unauthenticated route
- Invariant to test: an attacker-chosen referrer cannot enumerate or act on stacks the caller shouldn't see
- Expected Immunefi impact: High — Unauthenticated disclosure of stack state, task streams, or deploy output
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

# Q4528: Path/param injection: MergeRequest.extract_number URL confusion

## Question
Can an unprivileged attacker supply input where `extract_number` matches `https://<github domain>/<owner>/<repo>/pull/<n>` and only checks owner/name equality case-insensitively, breaking the assumption that a merge request number can only be requested for the stack's own repository?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`extract_number` matches `https://<github domain>/<owner>/<repo>/pull/<n>` and only checks owner/name equality case-insensitively)
- Exploit idea: a merge request number can only be requested for the stack's own repository is assumed; the parsing/joining logic `extract_number` matches `https://<github domain>/<owner>/<repo>/pull/<n>` and only checks owner/name equality case-insensitively
- Invariant to test: a merge request number can only be requested for the stack's own repository
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

# Q0266: Path/param injection: commit-message Merge-Requested-By spoof

## Question
Can an unprivileged attacker supply input where `User.find_or_create_author_from_github_commit` parses `^Merge-Requested-By: ([\w\-.]+)$` from the commit message and resolves that login, breaking the assumption that commit authorship attribution cannot be forged by writing a header line into a commit message?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`User.find_or_create_author_from_github_commit` parses `^Merge-Requested-By: ([\w\-.]+)$` from the commit message and resolves that login)
- Exploit idea: commit authorship attribution cannot be forged by writing a header line into a commit message is assumed; the parsing/joining logic `User.find_or_create_author_from_github_commit` parses `^Merge-Requested-By: ([\w\-.]+)$` from the commit message and resolves that login
- Invariant to test: commit authorship attribution cannot be forged by writing a header line into a commit message
- Expected Immunefi impact: Critical — Unauthorized deploy/rollback/merge of attacker-controlled code
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

# Q1189: Path/param injection: Stack#base_path directory traversal

## Question
Can an unprivileged attacker supply input where `Stack#base_path` is `Rails.root.join('data','stacks', repo_owner, repo_name, environment)`; repo_owner/name come from `to_param`/`from_param!` splitting on `/`, breaking the assumption that a crafted repo_owner/name/environment segment escapes the intended per-stack directory used for git checkouts and deploys?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`Stack#base_path` is `Rails.root.join('data','stacks', repo_owner, repo_name, environment)`; repo_owner/name come from `to_param`/`from_param!` splitting on `/`)
- Exploit idea: a crafted repo_owner/name/environment segment escapes the intended per-stack directory used for git checkouts and deploys is assumed; the parsing/joining logic `Stack#base_path` is `Rails.root.join('data','stacks', repo_owner, repo_name, environment)`; repo_owner/name come from `to_param`/`from_param!` splitting on `/`
- Invariant to test: a crafted repo_owner/name/environment segment escapes the intended per-stack directory used for git checkouts and deploys
- Expected Immunefi impact: Critical — Remote Code Execution on the Shipit deploy host (HackerOne/Immunefi RCE class)
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

# Q5369: Path/param injection: avatar_url URI.parse handling

## Question
Can an unprivileged attacker supply input where `User#avatar_uri` does `URI.parse(avatar_url)` on a GitHub-sourced string used in views, breaking the assumption that a hostile avatar_url cannot inject a javascript:/data: URI or SSRF target into rendered output?

## Target
- File/function: app/models/shipit/stack.rb + app/models/shipit/repository.rb + app/models/shipit/merge_request.rb + app/controllers/shipit/merge_status_controller.rb
- Entrypoint: Globbed engine routes (*stack_id/*id/*repo) and webhook-driven model lookups
- Attacker controls: the path segments / referrer / commit message (`User#avatar_uri` does `URI.parse(avatar_url)` on a GitHub-sourced string used in views)
- Exploit idea: a hostile avatar_url cannot inject a javascript:/data: URI or SSRF target into rendered output is assumed; the parsing/joining logic `User#avatar_uri` does `URI.parse(avatar_url)` on a GitHub-sourced string used in views
- Invariant to test: a hostile avatar_url cannot inject a javascript:/data: URI or SSRF target into rendered output
- Expected Immunefi impact: High — Session fixation / forced OAuth completion / clickjacking into a state-changing action
- Fast validation: minitest: feed the crafted param/segment to from_param!/extract_number/base_path, assert the resolved stack/path/identity is confined to the intended tenant.

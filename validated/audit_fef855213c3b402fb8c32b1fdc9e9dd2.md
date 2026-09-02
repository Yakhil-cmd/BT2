### Title
Cross-repository stack `unarchive!`/`archive!` via mismatched `repository.owner.login`/`repository.full_name` fields in signed-but-secretless webhook payloads - ([File: app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/secret to validate against using `params.dig('repository','owner','login')`, but `LabeledHandler` (and its sibling PR handlers) resolve the target `Repository`/`Stack` using the independently-attacker-controlled `params.repository.full_name`. Because these two fields are never cross-checked, an attacker who can get a payload accepted under any org whose `webhook_secret` is nil can set `full_name` to point at an entirely different, victim repository and drive `stack.archive!`/`stack.unarchive!` on it.

### Finding Description
The broken binding, stated explicitly: `repository_owner (used to pick the signing secret) == repository.full_name's owner (used to select the mutated Stack)` is assumed but never enforced.

Trace:
- `WebhooksController#verify_signature` computes `repository_owner = params.dig('repository','owner','login')` and calls `Shipit.github(organization: repository_owner).verify_webhook_signature(...)`, per [1](#0-0) . This picks the `GitHubApp` config for that org string only, purely to choose which secret to HMAC against.
- `GitHubApp#verify_webhook_signature` returns `true` unconditionally when that org's config has no `webhook_secret` set — `return true unless webhook_secret` — [2](#0-1) . This is the documented "secretless org" state (`webhook_secret: # nil` is a supported config value per `docs/setup.md`), and the question stipulates this precondition is met for the attacker's own org.
- Once verification is bypassed, `LabeledHandler#repository` resolves the acted-upon repository from a **completely separate field**, `params.repository.full_name`, via `Shipit::Repository.from_github_repo_name` — [3](#0-2) . That lookup is a pure DB `find_by(owner:, name:)` on the `owner/name` parsed out of `full_name`, with no reference at all to `repository.owner.login` — [4](#0-3) .
- `LabeledHandler#handle` then calls `stack.archive!`/`stack.unarchive!` on `Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter`, scoped to `repository.review_stacks` of the repository resolved from `full_name` — [5](#0-4) . `ReviewStackAdapter#unarchive!`/`#archive!` perform the real state mutation, including moving the stack in/out of the provisioning queue — [6](#0-5) .

Exploit flow: attacker POSTs to `/webhooks` with `X-Github-Event: pull_request`, a JSON body where `repository.owner.login` = some org X that is configured in this Shipit instance with `webhook_secret` nil (attacker need not control anything on GitHub for org X — it's just a string picked to satisfy the signature-selection step), and `repository.full_name` = `"victim-org/victim-repo"` (the real, tracked victim repository), plus a forged `pull_request.labels` array containing/excluding the victim's `provisioning_label_name` to drive `archive?`/`unarchive?` as desired. No `X-Hub-Signature` header content matters once `webhook_secret` is blank for org X.

Why existing guards fail: `verify_signature`/`GithubApp#verify_webhook_signature` only gate on the presence and correctness of an HMAC tied to whichever org string appears in `repository.owner.login`; they never assert that this org matches the owner encoded in `repository.full_name`, nor that the two fields refer to the same repository record. `ExplicitParameters` (`params do ... end` in `LabeledHandler`) only validates types/shape of `repository.full_name`, not ownership consistency with `repository.owner.login` (which per the payload schema isn't even required by this handler at all). There is no session, `current_user`, or `require_permission!` check anywhere on this webhook path.

### Impact Explanation
This lets a payload nominally "authenticated" against org X's (secretless) app config mutate the archived state of a `Stack` belonging to a completely unrelated victim repository/org, matching "a payload for one repository mutating another's stack" (Critical). Concretely, `unarchive!` re-enables a previously archived review stack for deploy-eligibility/provisioning without the victim repo maintainers' consent, and `archive!`/`unarchive!` can be replayed repeatedly and against any tracked repository in the same Shipit instance, since the only constraint is knowing (or guessing) one org configured without a webhook secret and the victim's real `owner/name`. Blast radius spans every repository tracked by the Shipit instance, not just the attacker's own.

### Likelihood Explanation
Preconditions: the Shipit instance must have at least one GitHub App organization configured with `webhook_secret` left blank — an officially supported and documented configuration (`docs/setup.md`, `config/secrets.development.example.yml`), commonly used for local/dev setups and, per the multi-org docs, per-org. The attacker needs no GitHub credentials, no Shipit session, and no knowledge beyond the victim's `owner/name` string (visible publicly on GitHub) and the name of any secretless org configured in the target instance. Cost is a single unauthenticated HTTP POST; the action is trivially repeatable.

### Recommendation
In `WebhooksController#verify_signature`/`create`, cross-validate that `params.dig('repository','owner','login')` matches the owner encoded in `params.dig('repository','full_name')` before dispatching to handlers, and reject (422) on mismatch. Additionally, `LabeledHandler`/sibling PR handlers should not trust `full_name` alone for stack resolution when a secretless org is in play — consider requiring `webhook_secret` for any org expected to be reachable from the internet, or binding repository resolution to the verified `repository_owner` field rather than the independently-supplied `full_name`.

### Proof of Concept
Minitest plan (`test/controllers/webhooks_controller_test.rb` style, no live GitHub):
1. Configure `Shipit.github` with two orgs: `"secretless-org"` (webhook_secret: nil) and the victim's real org (with a proper `webhook_secret` configured, or simply exists as a tracked `Repository`).
2. Create a victim `Shipit::Repository` (owner: `"victim-org"`, name: `"victim-repo"`) with `review_stacks_enabled: true`, `provisioning_behavior: :prevent_with_label`, `provisioning_label_name: "deploy-me"`, and an archived `ReviewStack`/`Stack` (`stack.archive!(user)`).
3. POST to `/webhooks` with header `X-Github-Event: pull_request`, no valid signature (or any signature — irrelevant since org is secretless), and JSON body: `action: "labeled"`, `repository: { full_name: "victim-org/victim-repo", owner: { login: "secretless-org" } }`, `pull_request: { state: "open", labels: [] , ... }` (label omitted to trigger `unarchive?` under `prevent_with_label`).
4. Assert response is `:ok` and `assert_not victim_stack.reload.archived?` — proving the victim's stack was unarchived by a payload "verified" only against the unrelated `secretless-org` config, with `repository.owner.login != repository.full_name`'s owner.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-49)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified

      Rails.logger.info([
        'WebhookController#verify_signature',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "signature=#{request.headers['X-Hub-Signature']}",
        "status=#{status}"
      ].join(' '))
    rescue Shipit::GithubOrganizationUnknown => e
      head(422)
      Rails.logger.warn([
        'WebhookController#verify_signature',
        'Webhook from unknown organization',
        "event=#{event}",
        "repository_owner=#{repository_owner}",
        "unknown_organization=#{e.message}",
        "status=#{status}"
      ].join(' '))
    end
```

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-63)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
          end

          def stack
            @stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-50)
```ruby
          def archive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no Stack exists. Ignoring."
              )
              return true
            end
            return if stack.archived?

            stack.remove_from_provisioning_queue
            stack.deprovision
            stack.archive!(user, *args, &block)
          end

          def unarchive!(*args, &block)
            if stack.blank?
              Rails.logger.info(
                "Processing #{action} event for #{repo_name} PR #{pr_number} but no ReviewStack exists. Creating."
              )
              return create!
            end
            return unless stack.archived?

            stack.transaction do
              Shipit::ReviewStackProvisioningQueue.add(stack)
              stack.unarchive!(*args, &block)
            end
          end
```

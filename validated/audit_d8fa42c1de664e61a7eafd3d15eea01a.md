This confirms the decoupling: `Repository.from_github_repo_name` looks up records purely by `owner`/`name` parsed from `params.repository.full_name` [1](#0-0) , with no cross-check against whichever organization's secret authenticated the request in `WebhooksController#verify_signature` [2](#0-1) .

### Title
Webhook signature validation is keyed on `repository.owner.login`, not on `repository.full_name` used by handlers - Cross-org stack/PR forgery - (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit/github_app.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
`Shipit::WebhooksController#verify_signature` selects which GitHub App/secret to validate against using `repository_owner`, itself read straight out of the attacker-controlled JSON body (`params.dig('repository','owner','login')`), while every downstream handler (e.g. `LabelCapturingHandler`) resolves the actual target `Stack`/`Repository` using a *different* attacker-controlled field, `params.repository.full_name`. In a multi-org Shipit deployment where at least one configured organization has no `webhook_secret` set (a documented, supported configuration - see `docs/setup.md` "Using Multiple Github Applications" and `config/secrets.development.shopify.yml`), an attacker can pick that no-secret org as `repository.owner.login` to sail through signature verification for free, while setting `repository.full_name` to `victim-org/victim-repo`, whose stack has `blocking_statuses` configured. The forged `pull_request` `unlabeled` payload is then processed against the victim's `ReviewStack`.

### Finding Description
The broken binding, as an explicit equality that the code assumes but never enforces:

`repository_owner` used in `verify_signature` (`params.dig('repository','owner','login')`) **is assumed to equal** the owner embedded in `params.repository.full_name` used later by `LabelCapturingHandler#repository` (`Shipit::Repository.from_github_repo_name(params.repository.full_name)`).

These are two independent reads of the same untrusted JSON body:
- `app/controllers/shipit/webhooks_controller.rb:59-62` – `repository_owner` picks the GitHub App config (and thus which `webhook_secret`, if any, is required) via `Shipit.github(organization: repository_owner)` [2](#0-1) .
- `lib/shipit.rb:170-200` – `Shipit.github`/`github_app_config` look up the org's config by name; if that org's `webhook_secret` is blank, `GitHubApp#verify_webhook_signature` returns `true` unconditionally regardless of the signature header supplied [3](#0-2) .
- `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb:110-118` – the handler resolves the affected `Repository`/`Stack` using `params.repository.full_name`, completely independent of `repository_owner` [4](#0-3) .
- `app/models/shipit/repository.rb:53-56` – `from_github_repo_name` performs a plain lookup by `owner`/`name` parsed from that same `full_name`, with no reference back to whichever org secret authenticated the request [1](#0-0) .

Nothing in `drop_unhandled_event`, `check_if_ping`, or `ExplicitParameters` (`params do requires :repository do requires :full_name, String end end` in the handler) checks that `full_name`'s owner segment matches `repository.owner.login`/the org whose secret validated the signature.

Exploit flow:
1. Shipit is configured for multiple GitHub orgs (a documented supported mode), one of which ("no-secret-org") has `webhook_secret` left blank.
2. Attacker sends `POST /webhooks` with header `X-Github-Event: pull_request`, `X-Hub-Signature: sha1=<anything>` (accepted format, but irrelevant here since the secret is blank so verification is skipped entirely) and a JSON body where `repository.owner.login = "no-secret-org"` but `repository.full_name = "victim-org/victim-repo"`, `action = "unlabeled"`, and `pull_request.labels` set to arbitrary attacker-chosen names.
3. `verify_signature` calls `Shipit.github(organization: "no-secret-org")`, whose `webhook_secret` is blank, so `verify_webhook_signature` returns `true` without checking anything.
4. `Shipit::Webhooks.for_event('pull_request')` dispatches to `LabelCapturingHandler` (and `UnlabeledHandler`), both of which resolve `repository`/`stack` from `params.repository.full_name = "victim-org/victim-repo"`.
5. `LabelCapturingHandler#capture_labels` runs `pull_request.update!(labels: params.pull_request.labels.map(&:name))` on the victim stack's `PullRequest` record [5](#0-4) .
6. Those labels are later surfaced by `ReviewStack#env`, which upcases each label name into an environment variable set to `"true"` and merges it into the deploy/task environment [6](#0-5) , consumed by `TaskCommands#env`/`DeployCommands` and ultimately passed into commands run for that stack.
7. Separately, a forged `status` webhook (subject to the same owner/full_name decoupling) can create/clear a blocking status on the victim commit, and `Commit#blocked?` gates `deployable?` purely from `stack.blocking_statuses` and the commit graph, with no owner cross-check either [7](#0-6) .

### Impact Explanation
An attacker who controls (or simply names) any org configured without a `webhook_secret` in a multi-org Shipit deployment can write arbitrary `PullRequest#labels` — and, via chained `status`/other webhook types using the same `repository_owner` vs `repository.full_name` decoupling, other stack-affecting state — onto **any other organization's repository/stack**, including ones with `webhook_secret` properly configured. This is a payload for one repository mutating another repository's records, matching the Critical category ("a payload for one repository mutating another's stack, commit, task or team"). Because attacker-controlled label names become uppercased environment variables merged into the deploy/task command environment (`ReviewStack#env`, `TaskCommands#env`), and blocking statuses gate `deployable?`, this can influence what environment variables are present during a deploy and whether a deploy is blocked/unblocked for the victim stack. The attack is repeatable against any victim repo/org as long as one no-secret org exists in the shared multi-org config.

### Likelihood Explanation
This requires the operator to run Shipit in the documented "Using Multiple Github Applications" mode with at least one org's `webhook_secret` left blank (shown as a valid, blank-by-default option in `docs/setup.md`, `config/secrets.development.shopify.yml`, and `test/dummy/config/secrets_double_github_app.yml`). This is not a hypothetical edge case — the shipped example configs and docs default `webhook_secret` to blank/commented-out. Given that precondition, the attack costs nothing (a single unauthenticated HTTP POST), requires no GitHub credentials, and is fully repeatable.

### Recommendation
Bind webhook authentication to the repository actually acted upon, not to a separately-read field of the same untrusted payload:
- After selecting the GitHub App config for verification, re-derive `repository_owner` from the same field used by handlers (`repository.full_name`'s owner segment) so both reads agree, or better, verify the signature using the config keyed by the *stored* `Repository#owner` looked up from `full_name`, rather than trusting `repository.owner.login` from the payload.
- Do not allow a "no-secret" org's absence of `webhook_secret` to validate payloads whose `full_name` belongs to a different, secret-configured org. Consider requiring `webhook_secret` to be present for every org that has any provisioned repository, or reject payloads where `repository.owner.login` doesn't case-insensitively match the owner segment of `repository.full_name`.

### Proof of Concept
minitest plan (webhooks controller / handler level, no live GitHub):
```ruby
test "pull_request payload with mismatched owner/full_name and a no-secret org bypasses signature and mutates victim stack" do
  # Arrange: multi-org secrets fixture where OrgOne has no webhook_secret (as in
  # test/dummy/config/secrets_double_github_app.yml), and a victim stack under a
  # DIFFERENT, secret-configured org with blocking_statuses configured.
  victim_repo = shipit_repositories(:shipit) # owner: e.g. "shopify", secret-protected
  victim_stack = create_stack_with_blocking_statuses(victim_repo)

  payload = payload_parsed(:pull_request_unlabeled)
  payload["repository"]["owner"]["login"] = "OrgOne"      # no-secret org
  payload["repository"]["full_name"] = victim_repo.github_repo_name # victim org/repo
  payload["pull_request"]["labels"] = [{ "name" => "attacker-label" }]

  request.headers['X-Github-Event'] = 'pull_request'
  request.headers['X-Hub-Signature'] = 'sha1=deadbeef' # arbitrary/invalid, irrelevant since OrgOne has no secret

  assert_difference -> { victim_stack.pull_request.reload.labels.count } do
    post :create, body: payload.to_json, as: :json
  end

  assert_includes victim_stack.pull_request.reload.labels, "attacker-label"
  # Binding check: repository_owner ("OrgOne") != victim_repo.owner, yet victim_stack was mutated.
  assert_not_equal "OrgOne", victim_repo.owner
end
```
This demonstrates the equality `repository_owner == owner(repository.full_name)` is violated while the request is still accepted and mutates the victim's `PullRequest`/`Stack` state.

### Citations

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/controllers/shipit/webhooks_controller.rb (L24-30)
```ruby
    def verify_signature
      github_app = Shipit.github(organization: repository_owner)
      verified = github_app.verify_webhook_signature(
        request.headers['X-Hub-Signature'],
        request.raw_post
      )
      head(422) unless verified
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-118)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end

          def stack
            @stack ||= review_stack.stack
          end
```

**File:** app/models/shipit/review_stack.rb (L84-93)
```ruby
    def env
      return super unless pull_request.present?

      super
        .merge(
          pull_request
            .labels
            .each_with_object({}) { |label_name, labels| labels[label_name.upcase] = "true" }
        )
    end
```

**File:** app/models/shipit/commit.rb (L227-237)
```ruby
    def deployable?
      !locked? && (stack.ignore_ci? || (success? && !blocked?))
    end

    def blocked?
      return false if stack.blocking_statuses.empty?

      # TODO: Perfs might be horrible here if the range is big.
      # We should look at fetching the undeployed commits only once
      stack.commits.reachable.newer_than(stack.last_deployed_commit).older_than(self).any?(&:blocking?)
    end
```

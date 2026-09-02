### Title
Repository-to-signing-org binding is not enforced, allowing a forged `pull_request.labeled`/`unlabeled` payload to overwrite another organization's `PullRequest#labels` - ([File: app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb])

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to check using `repository_owner` (`params.dig('repository','owner','login')` / `params.dig('organization','login')`), a value read from the attacker-controlled JSON body. `LabelCapturingHandler#repository`/`#capture_labels` and `Handler#stacks` instead resolve the target `Repository`/`Stack` from a *different* field in the same body, `params.repository.full_name`. Nothing ties these two fields together, so a payload whose `repository.owner.login` matches the org used to validate the signature, but whose `repository.full_name` names an unrelated organization's repository, is processed as authentic for that unrelated org, letting `pull_request.update!(labels: params.pull_request.labels.map(&:name))` overwrite the victim's stored `PullRequest#labels`.

### Finding Description
The intended binding is: `organization that validated the webhook signature == organization owning the Repository/Stack/PullRequest being mutated`. In code these are computed from two independently attacker-suppliable JSON fields of the same raw POST body:

- Signature/org selection: `WebhooksController#repository_owner` reads `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`, then `Shipit.github(organization: repository_owner)` picks the per-org config/secret used by `GitHubApp#verify_webhook_signature`. [1](#0-0) [2](#0-1) 

- Target resolution/mutation: `LabelCapturingHandler#repository` looks up `Shipit::Repository.from_github_repo_name(params.repository.full_name)`, and `#capture_labels` writes `stack.pull_request.update!(labels: params.pull_request.labels.map(&:name))`. [3](#0-2) 

`GitHubApp#verify_webhook_signature` also short-circuits to `true` whenever no `webhook_secret` is configured for the selected organization, `return true unless webhook_secret`, meaning any org entry without a configured secret authenticates arbitrary payload content for that `repository_owner` value. [4](#0-3) 

Because `repository.owner.login` and `repository.full_name` are simply two keys of the same attacker-supplied JSON body sent to `POST /webhooks`, an attacker who can produce (or trivially satisfy, via an org with no configured secret) a valid signature keyed to `repository.owner.login = "orgA"` can set `repository.full_name = "orgB/victim-repo"` in the same payload. `LabelCapturingHandler` never checks that `repository.full_name`'s owner segment equals `repository_owner`; it only uses `full_name` to look up the `Repository`, then the `Stack`/`PullRequest` belonging to org B, and overwrites its `labels`.

Guard review: `verify_signature` only authenticates "did this HMAC match the secret picked by the payload's own `repository_owner` field" — it never re-derives or cross-checks the repository actually referenced by `repository.full_name`. `drop_unhandled_event` and the `ExplicitParameters` schema only validate shape/presence, not cross-field consistency (`repository.full_name` vs `repository.owner.login`). `force_github_authentication`/`User#authorized?`/`require_permission!` are session/API-token guards unrelated to this webhook path. No model validation on `PullRequest#labels` enforces the writing org. None of these existing guards close the gap.

For the write to actually land, `stack` must already exist for the *victim* repo (`ReviewStack` matching `environment: "pr#{params.number}"`, from `ReviewStackAdapter#stack` scoped by `repository.review_stacks`), and for `labeled`/`unlabeled` events it must not be archived — both discoverable by an attacker simply browsing the victim's public repository/PRs. [5](#0-4) [6](#0-5) 

### Impact Explanation
An attacker can overwrite `PullRequest#labels` for any org/repo/PR that has an active `ReviewStack`, without ever authenticating as that org. This includes injecting or removing the `provisioning_label_name` string, which `labeled_handler.rb`/`opened_handler.rb`/`unlabeled_handler.rb` subsequently use to decide `archive!`/`unarchive!`/provisioning behavior on the victim's stack, i.e., a payload authenticated for one repository mutates state for a different, unrelated repository's stack/PR. This matches the Critical category "a payload for one repository mutating another's stack." Impact is repeatable against any repository/organization onboarded to the same multi-tenant Shipit instance, provided a matching active `ReviewStack` exists.

### Likelihood Explanation
Exploitability depends on the attacker being able to produce (or trivially bypass, via an unsecured `webhook_secret` entry) a signature validated against the `repository_owner` value embedded in their own forged body — this is the only nontrivial precondition, and the question's premise grants it. Beyond that, the attacker needs no session, API token, or team membership, and only needs to know or guess a target PR number with an existing `ReviewStack` (trivially discoverable on public repos). The direct `POST /webhooks` endpoint accepts arbitrary raw JSON bodies and headers, so the attack is a single crafted HTTP request, fully repeatable against arbitrary target repositories/stacks.

### Recommendation
In `WebhooksController#verify_signature` (or in `Handler`), require that the organization used to select the signing secret (`repository_owner`) matches the owner segment of `payload.dig('repository','full_name')` (and of `organization.login` if present) before dispatching to handlers; reject the request otherwise. Additionally, do not allow `GitHubApp#verify_webhook_signature` to silently return `true` when `webhook_secret` is blank — treat missing secret as a hard misconfiguration/deny, or gate it strictly to test/dev environments.

### Proof of Concept
Add a minitest to `test/models/shipit/webhooks/handlers/pull_request/label_capturing_handler_test.rb`-style test (or a controller test) that:
1. Creates two `Repository` records for `orgA/repoA` and `orgB/repoB`, each with an active `ReviewStack`/`PullRequest` for `orgB/repoB` pr number `N`, with `PullRequest.labels = ["safe-label"]`.
2. Configures `Shipit.github_apps`/secrets such that `orgA` has a known `webhook_secret` (or no secret, exercising the `return true unless webhook_secret` path).
3. Builds a payload: `action: "labeled"`, `repository: { full_name: "orgB/repoB", owner: { login: "orgA" } }`, `pull_request.number = N`, `pull_request.labels = [{ name: <provisioning_label_name> }]`.
4. Computes/uses the valid signature for `orgA` (or none, in the no-secret variant) and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
5. Asserts, BEFORE: `orgB/repoB`'s `PullRequest.reload.labels == ["safe-label"]`.
6. Asserts, AFTER the request: `orgB/repoB`'s `PullRequest.reload.labels` now includes `provisioning_label_name`, proving org A's signature authenticated a mutation of org B's `PullRequest`, and that a subsequent `labeled_handler`/`opened_handler` run would incorrectly trigger archive/unarchive/provisioning logic on `orgB`'s stack.

### Citations

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L62-72)
```ruby
          def labeled_active_stack?
            labeled? && stack.present? && !stack.archived?
          end

          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end

          def reopened_active_stack?
            reopened? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-114)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end

          def review_stack
            @review_stack ||=
              Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks)
          end

          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-17)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end
```

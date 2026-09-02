### Title
Webhook signature verification is bound to `repository.owner.login`, not `repository.full_name`, allowing a no-secret organization to forge `pull_request` events (e.g. `unlabeled`) that mutate any tracked repository's `LabelCapturingHandler` state - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`Shipit::WebhooksController#verify_signature` selects the `GitHubApp` (and thus the `webhook_secret` used for HMAC verification) using only `params.dig('repository','owner','login')`, while `LabelCapturingHandler#repository` resolves the target `Shipit::Repository`/stack using the independent `params.repository.full_name` field in the same JSON body. If any organization configured in Shipit's multi-org github secrets has a blank `webhook_secret`, `GitHubApp#verify_webhook_signature` returns `true` unconditionally, letting an attacker forge a `pull_request` payload whose `repository.owner.login` names that no-secret org but whose `repository.full_name` names an entirely different, victim-owned repository/stack.

### Finding Description
The broken binding, stated as an equality that the code fails to enforce:

`authenticated_org = params.repository.owner.login` MUST equal `acted_upon_repo.owner = params.repository.full_name.split('/').first` for every write the handler performs. Shipit never checks this equality.

Trace:
1. `before_action :check_if_ping, :drop_unhandled_event, :verify_signature` runs before `create`. [1](#0-0) 
2. `verify_signature` computes `github_app = Shipit.github(organization: repository_owner)` where `repository_owner` is `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [2](#0-1) [3](#0-2) 
3. `Shipit.github(organization:)` resolves per-org config via `github_app_config(organization)` when multiple orgs are configured (`TOP_LEVEL_GH_KEYS`/`github_default_organization` logic), so distinct orgs can have distinct `webhook_secret` values, including a blank one. [4](#0-3) 
4. `GitHubApp#verify_webhook_signature` short-circuits to `true` whenever `webhook_secret` is blank, with no signature computed or compared. [5](#0-4) 
5. Once `verify_signature` passes (silently, for the no-secret org), `create` parses the raw body and dispatches to `Shipit::Webhooks.for_event(event)` handlers, including `LabelCapturingHandler`. [6](#0-5) 
6. `LabelCapturingHandler#repository` looks up the actual target repository using `params.repository.full_name` — a field the controller never examined and never tied to the org that "authenticated" the request. [7](#0-6) 
7. For `action=unlabeled` on an existing, non-archived review stack, `capture_labels?` returns true via `unlabeled_active_stack?`, and `capture_labels` persists `params.pull_request.labels.map(&:name)` onto `stack.pull_request`. [8](#0-7) [9](#0-8) 

Root cause: the trust boundary check (`verify_signature`) and the resource-selection logic (`repository`/`stack` in the handler) read two different, independently attacker-controlled JSON paths (`repository.owner.login` vs `repository.full_name`) from the same forged payload, with no cross-validation that they refer to the same repository/organization. Combined with the documented "no-secret organization" gap (`return true unless webhook_secret`), an attacker who merely knows the name of one Shipit-configured org that has no `webhook_secret` set can forge a payload targeting any *other* tracked repository's review stack.

Exploit flow: attacker (unprivileged, no Shipit credentials) sends `POST /webhooks` with header `X-Github-Event: pull_request`, no valid `X-Hub-Signature` needed, and JSON body:
```json
{
  "action": "unlabeled",
  "number": 1,
  "repository": { "owner": {"login": "no-secret-org"}, "full_name": "victim-org/victim-repo" },
  "pull_request": { ..., "labels": [{"name": "malicious-value"}] },
  "sender": {"login": "attacker"}
}
```
Because `no-secret-org`'s config has no `webhook_secret`, `verify_signature` passes. `LabelCapturingHandler` then resolves `victim-org/victim-repo`'s review stack (which has `review_stacks_enabled: true`, `provisioning_behavior: allow_all`, so it auto-provisions review stacks for any external PR) and overwrites its `PullRequest#labels`.

Existing guards checked and why they don't stop this: `drop_unhandled_event` only checks the event type is registered, not the payload contents. `ExplicitParameters` schema (`params do ... end` in the handler) only validates types/presence, not cross-field consistency between `repository.owner.login` and `repository.full_name`. `force_github_authentication`/`User#authorized?`/`require_permission!` are irrelevant — this is an unauthenticated webhook endpoint by design, whose only intended security boundary is the HMAC signature, which is exactly the boundary broken here.

### Impact Explanation
The attacker can write attacker-chosen label names onto the `PullRequest` record of a review stack belonging to a repository the attacker did not open the PR in and does not control — i.e., a payload authenticated (nominally) for one repository mutates another repository's stack data, matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." Per the question's stated downstream chain, those label names are surfaced as uppercased environment variable keys via `ReviewStack#env`, which (if true, as asserted in the target description) are merged into the environment used when running `shipit.yml`-defined commands via `Command`/`PTY.spawn` for that review stack's deploy/task execution — turning an unauthenticated cross-tenant write into a path toward command execution with attacker-influenced environment on the deploy host. This is repeatable against any repository tracked by Shipit as long as one no-secret org exists anywhere in the multi-org config, and the blast radius spans every repository/organization configured in the same Shipit instance, not just the no-secret org itself.

### Likelihood Explanation
Preconditions: (1) Shipit must be configured with multiple GitHub organizations (per-org secrets), and at least one of them must have a blank/missing `webhook_secret` — a configuration gap, not a code bug in isolation, but one the code does nothing to prevent or warn about. (2) A victim repository/stack must be tracked by Shipit with `review_stacks_enabled: true` and `provisioning_behavior: allow_all` (a common, documented configuration for review stacks). Attacker cost is minimal: knowledge of the no-secret org's login name (which may be discoverable, e.g., via error responses, docs, or trial), no valid HMAC, no session, no API token. The request is a single unauthenticated `POST /webhooks` and is fully repeatable/scriptable against arbitrary target repositories by only changing `repository.full_name` in the JSON body.

### Recommendation
Bind the webhook's authentication to the same repository identity used for resource resolution: after signature verification, re-derive the organization from `params.repository.full_name` (not `repository.owner.login` alone) and reject if the two disagree, or better, verify the signature using the config resolved from `repository.full_name`'s owner. Additionally, treat a configured organization with a blank `webhook_secret` as a hard misconfiguration: refuse to process webhooks for such organizations (fail closed) rather than silently accepting unsigned payloads, and require `webhook_secret` to be present for every organization entry at boot/config-validation time.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` style, to be added under `test/`):
1. Configure `Rails.application.credentials.github` with two orgs: `"secret-org"` (has `webhook_secret: "s3cr3t"`) and `"no-secret-org"` (no `webhook_secret` key).
2. Create `victim_repository = Shipit::Repository.create!(name: "victim-repo", owner: "secret-org", review_stacks_enabled: true, provisioning_behavior: :allow_all)`.
3. Provision an active (non-archived) review stack + `PullRequest` for that repository (e.g., via `OpenedHandler` with `repository.full_name: "secret-org/victim-repo"`), and record `original_labels = stack.pull_request.labels`.
4. POST to `/webhooks` with header `X-Github-Event: pull_request`, **no** `X-Hub-Signature` header (or an arbitrary invalid one), and JSON body: `action: "unlabeled"`, `repository.owner.login: "no-secret-org"`, `repository.full_name: "secret-org/victim-repo"`, `pull_request.labels: [{"name" => "INJECTED"}]`.
5. Assert response is `200`, and assert `stack.pull_request.reload.labels == ["INJECTED"]`, proving `original_labels != stack.pull_request.reload.labels`, i.e., the equality `authenticated_org == acted_upon_repo.owner` was violated and a write occurred for a repository that never authenticated the request.
6. Negative control: repeat with `repository.owner.login: "secret-org"` (which has a real secret) and no valid signature; assert response `422` and no label mutation, confirming the divergence is specific to the no-secret-org bypass combined with cross-field repository confusion.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L6-6)
```ruby
    before_action :check_if_ping, :drop_unhandled_event, :verify_signature
```

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** lib/shipit.rb (L170-200)
```ruby
  def github(organization: github_default_organization)
    # Backward compatibility
    # nil signifies the single github app config schema is being used
    if github_default_organization.nil?
      config = secrets.github
    else
      config = github_app_config(organization)
      raise GithubOrganizationUnknown, organization if config.nil?
    end
    @github ||= {}
    @github[organization] ||= GitHubApp.new(organization, config)
  end

  def github_default_organization
    return nil unless secrets&.github

    org = secrets.github.keys.first
    TOP_LEVEL_GH_KEYS.include?(org) ? nil : org
  end

  def github_organizations
    return [nil] unless github_default_organization

    secrets.github.keys
  end

  def github_app_config(organization)
    github_config = secrets.github.deep_transform_keys(&:downcase)
    github_organization = organization.downcase.to_sym
    github_config[github_organization]
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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L66-68)
```ruby
          def unlabeled_active_stack?
            unlabeled? && stack.present? && !stack.archived?
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L98-102)
```ruby
          def capture_labels
            return unless pull_request = stack.pull_request

            pull_request.update!(labels: params.pull_request.labels.map(&:name))
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L110-114)
```ruby
          def repository
            @repository ||=
              Shipit::Repository
              .from_github_repo_name(params.repository.full_name) || NullRepository.new
          end
```

### Title
Cross-tenant PR label injection via organization-fallback webhook verification — (File: `app/controllers/shipit/webhooks_controller.rb`, `lib/shipit.rb`, `app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb`)

### Summary
In multi-organization Shipit deployments, the webhook signature verifier is selected using `repository_owner`, which falls back from `repository.owner.login` to the independently attacker-set `organization.login` field, while `LabelCapturingHandler` resolves its mutation target from the equally independent `repository.full_name` field. An attacker who legitimately owns one org onboarded to the shared Shipit instance can authenticate a forged `pull_request` webhook with their own org's `webhook_secret` while pointing `repository.full_name` at a victim repository belonging to a different org, causing `PullRequest#labels` on the victim's stack to be overwritten with attacker-chosen values.

### Finding Description
The broken binding: the code implicitly assumes `repository_owner (verifier selector) == repository.full_name's owner (mutation target)`, but nothing enforces this equality.

- `Shipit::WebhooksController#repository_owner` computes the verifier selector as `params.dig('repository','owner','login') || params.dig('organization','login')` [1](#0-0) , and `verify_signature` uses it to pick the `GitHubApp` instance: `Shipit.github(organization: repository_owner)` before checking the HMAC signature [2](#0-1) .
- `Shipit.github` looks up a per-organization secret via `github_app_config(organization)` and caches a distinct `GitHubApp` (and thus distinct `webhook_secret`) per organization key, whenever the install uses the multi-org secrets schema (`github_default_organization` non-nil) [3](#0-2) .
- `LabelCapturingHandler`'s schema only requires `repository.full_name` (not `repository.owner.login`) [4](#0-3) , and it resolves the target repository purely from that field: `Shipit::Repository.from_github_repo_name(params.repository.full_name)` [5](#0-4) , independent of whichever org's secret authenticated the request.
- On `action=unlabeled` for an active, non-archived stack, `capture_labels` persists attacker-supplied label names directly onto the victim's `PullRequest`: `pull_request.update!(labels: params.pull_request.labels.map(&:name))` [6](#0-5) [7](#0-6) .

Exploit request: attacker owns "attacker-org" with a real Shipit GitHub App installation and knows its `webhook_secret` (it's their own onboarded org). They POST to `/webhooks` with `X-Github-Event: pull_request` and a body such as:
```json
{
  "action": "unlabeled",
  "number": 42,
  "pull_request": { "...": "...", "labels": [{"name": "MALICIOUS_ENV_KEY"}] },
  "repository": { "full_name": "victim-org/victim-repo" },
  "organization": { "login": "attacker-org" },
  "sender": { "login": "attacker" }
}
```
signed with `attacker-org`'s `webhook_secret`. `repository_owner` resolves to `attacker-org` (no `repository.owner.login` present) so `verify_signature` succeeds using the attacker's own legitimate secret. `LabelCapturingHandler`, however, looks up `victim-org/victim-repo`'s stack and overwrites its `PullRequest#labels`.

Existing guards do not stop this: `verify_signature` only proves the request was signed by *some* org's secret, not that it matches the repository the handler will act on; the `ExplicitParameters` schema requires `repository.full_name` but not `repository.owner.login`, so this divergent-field construction is schema-valid; `drop_unhandled_event` and `force_github_authentication` are unrelated to this check.

### Impact Explanation
This is a cross-tenant write: an attacker authenticated only by their own org's secret mutates a `PullRequest` record belonging to a stack under a completely different org/repository they do not control. Because uploaded label names (`labels.map(&:name)`) later become uppercased environment variable keys via `ReviewStack#env`, this expands from label-metadata tampering to potential injection of attacker-controlled environment variable names into a victim's deploy/task environment — matching the Critical category "a payload for one repository mutating another's stack, commit, task or team." The attack is repeatable against any repository already registered in the shared Shipit instance, for every `pull_request` action the handler processes (`opened`, `labeled`, `unlabeled`, `reopened`).

### Likelihood Explanation
This requires the Shipit instance to be configured in multi-organization mode (`secrets.github` keyed by org, per `github_default_organization`/`github_app_config`) [8](#0-7) ; in legacy single-org mode `Shipit.github` ignores the `organization:` argument entirely (`github_default_organization.nil?` short-circuits to the single shared secret) [9](#0-8) , so the bug only manifests in shared/multi-tenant deployments — which is exactly the scenario the multi-org schema exists to support. Given that precondition, the attacker's cost is trivial: own one legitimate org onboarded to the instance, know its own `webhook_secret`, and send one crafted HTTP POST — no privileged Shipit role, session, or victim-org secret needed.

### Recommendation
Bind the signature-verification organization to the same field the handler uses for repository resolution. Concretely, derive `repository_owner` strictly from `repository.full_name`'s owner segment (or require `repository.owner.login` to be present and match `repository.full_name`'s owner) rather than falling back to the independently-controlled `organization.login`. Additionally, have each handler assert that the repository resolved for mutation belongs to the same organization that authenticated the webhook before performing any write.

### Proof of Concept
Under `test/controllers/webhooks_controller_test.rb` (multi-org fixture), add:
```ruby
test "pull_request unlabeled with organization fallback cannot mutate another org's stack" do
  # victim-org repo/stack fixture already exists with a review stack + pull_request
  victim_repo = "victim-org/victim-repo"
  attacker_secret = Shipit.github(organization: "attacker-org").send(:webhook_secret)

  payload = {
    action: "unlabeled",
    number: 42,
    pull_request: { id: 1, number: 42, url: "...", title: "t", state: "open",
                     additions: 1, deletions: 1,
                     head: { sha: "deadbeef", ref: "pull/42" },
                     user: { login: "attacker" }, assignees: [],
                     labels: [{ name: "INJECTED_ENV_KEY" }] },
    repository: { full_name: victim_repo }, # no owner.login
    organization: { login: "attacker-org" }, # fallback selector
    sender: { login: "attacker" }
  }.to_json

  signature = "sha1=" + OpenSSL::HMAC.hexdigest("sha1", attacker_secret, payload)

  post shipit.webhooks_path,
       params: payload,
       headers: { "X-Github-Event" => "pull_request", "X-Hub-Signature" => signature,
                  "Content-Type" => "application/json" }

  # Binding under test: repository_owner ("attacker-org") authenticated the request,
  # but the mutated record belongs to victim_repo's owner ("victim-org").
  # Assert the invariant "event only affects the repo whose secret authenticated it"
  pull_request = Shipit::Repository.from_github_repo_name(victim_repo).review_stacks.first.pull_request
  assert_not_includes pull_request.reload.labels, "INJECTED_ENV_KEY",
    "victim-org's PullRequest was mutated by a webhook authenticated with attacker-org's secret"
end
```
Before the fix, this assertion fails (the label is written); after binding `repository_owner` to `repository.full_name`'s owner, the request is rejected with `422` and the assertion passes.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/label_capturing_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
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

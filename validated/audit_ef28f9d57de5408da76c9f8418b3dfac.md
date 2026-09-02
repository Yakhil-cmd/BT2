### Title
Signing-org / target-repo confusion in webhook signature verification allows cross-tenant stack archive/unarchive - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb)

### Summary
`WebhooksController#verify_signature` derives the signing organization from `params.dig('repository', 'owner', 'login')`, while `LabeledHandler#repository` (and every other `PullRequest` handler) resolves the target `Repository`/`Stack` from the independent field `params.repository.full_name` via `Repository.from_github_repo_name`. Because nothing binds these two payload fields together, an attacker who owns a legitimate Shipit-registered organization ("attacker-org") can sign a `labeled` webhook with `repository.owner.login: "attacker-org"` (verified against attacker-org's own webhook secret) while setting `repository.full_name: "victim-org/prod-repo"`, causing the handler to look up and mutate the victim's real stack.

### Finding Description
The claimed binding is: `repository_owner used to select the verifying GitHubApp` == `repository whose Stack is looked up and mutated by the handler`. Tracing the code:

- `verify_signature` fetches the app for HMAC verification using `repository_owner`, which reads `params.dig('repository', 'owner', 'login')`: [1](#0-0)  and [2](#0-1) 
- `LabeledHandler#repository` resolves the target repo using a completely different field, `params.repository.full_name`: [3](#0-2) 
- `Repository.from_github_repo_name` does a raw string split/DB lookup on that field with no cross-check against `repository.owner.login`: [4](#0-3) 
- The `ExplicitParameters` schema for `LabeledHandler` only requires `repository.full_name`; it does not require or validate `repository.owner.login` at all, so the two fields are free to diverge: [5](#0-4) 
- `handle` then calls `stack.archive!`/`stack.unarchive!` on whatever stack was resolved via `full_name`: [6](#0-5) 
- `ReviewStackAdapter#archive!` performs real deprovisioning: `stack.remove_from_provisioning_queue`, `stack.deprovision`, `stack.archive!`: [7](#0-6) 

Exploit: attacker POSTs to `/webhooks` with `X-Github-Event: labeled`, body containing `repository.owner.login = "attacker-org"` (attacker knows this org's configured webhook secret because it's their own Shipit-registered tenant), `repository.full_name = "victim-org/prod-repo"`, and `pull_request.labels` containing victim's configured `provisioning_label_name`, `pull_request.state = "open"`, signed with `X-Hub-Signature` computed using attacker-org's secret. `verify_signature` calls `Shipit.github(organization: "attacker-org")` and succeeds because the signature was legitimately computed with that org's secret over that exact raw body — the HMAC check has no knowledge of, or dependency on, `full_name`. The handler then loads `victim-org/prod-repo`'s `Repository`, evaluates `archive?`/`unarchive?` against victim's `provisioning_behavior`/`provisioning_label_name`, and calls `stack.archive!` or `stack.unarchive!` on victim's live `ReviewStack`.

No existing guard prevents this: `verify_signature` only proves the raw body was signed by *some* known organization's secret, not that the organization matches the repository the handler will act on; the `ExplicitParameters` schema doesn't require `repository.owner.login` to be present or consistent with `full_name`; `Repository.from_github_repo_name` performs an unscoped lookup with no owner/signing-org cross-check.

### Impact Explanation
An attacker who controls one legitimate multi-tenant org registered in the same Shipit instance can force `Shipit::Stack#archive!`/`#deprovision` or `#unarchive!` to run against another tenant's `ReviewStack`, causing an unauthorized deprovision/rollback (or unwanted re-provision) of a victim's production-adjacent review stack, purely by crafting a `repository.full_name` value that doesn't match the org whose secret signed the request. This is a payload for one repository mutating another's stack — matching the Critical impact category. Repeatable against any victim repo/stack whose `full_name` the attacker can guess or enumerate, and applies identically to `UnlabeledHandler`, `OpenedHandler`, `ClosedHandler`, `ReopenedHandler`, and `EditedHandler`, which all use the same `params.repository.full_name`-based lookup pattern.

### Likelihood Explanation
Requires: (1) a multi-tenant Shipit deployment with per-organization `github` secrets/configs (documented and supported, see `secrets_double_github_app.yml`/`docs/setup.md` "Using Multiple Github Applications"), (2) attacker controls at least one such tenant org with review stacks/webhooks configured (their own legitimate webhook secret), (3) victim repo has `review_stacks_enabled` and a configured `provisioning_label_name`/`provisioning_behavior`, and (4) victim has an existing `ReviewStack` to toggle. Attacker cost is a single crafted HTTP POST with a valid HMAC computed from their own secret — no privileged Shipit session, GitHub token, or victim secret needed. Fully repeatable and scriptable.

### Recommendation
Bind the verified signing organization to the resolved repository: after `verify_signature` succeeds, re-derive/require that `repository.owner.login` (or the owner segment of `repository.full_name`) matches the organization used for `Shipit.github(organization:)`, and reject (422) if they diverge. Alternatively/additionally, have handlers resolve the `Repository` using the same `repository.owner.login` field that was used for signature verification instead of the independently-controlled `full_name`, or validate that `Repository#owner` (looked up via `full_name`) equals the `repository_owner` used to verify the signature before allowing any mutation.

### Proof of Concept
Minitest plan (webhooks_controller_test.rb or a dedicated integration test), no live GitHub:
1. Configure two orgs in test secrets, e.g. `attacker-org` and `victim-org`, each with distinct `webhook_secret`.
2. Create `Shipit::Repository` for `victim-org/prod-repo`, `review_stacks_enabled: true`, `provisioning_behavior: :prevent_with_label`, `provisioning_label_name: "deploy-prod"`, and an existing unarchived `Shipit::ReviewStack` for a PR environment.
3. Build a `labeled` payload: `repository: { owner: { login: "attacker-org" }, full_name: "victim-org/prod-repo" }`, `pull_request.state: "open"`, `pull_request.labels: [{ name: "deploy-prod" }]`, `action: "labeled"`.
4. Compute `X-Hub-Signature` using `attacker-org`'s `webhook_secret` over the exact raw JSON body.
5. POST to `/webhooks` with `X-Github-Event: labeled` and that signature.
6. Assert response is `:ok` (signature accepted) AND assert the victim's `ReviewStack` is archived/deprovisioned (`stack.reload.archived?` true, or `provision_status == "deprovisioning"`), proving `stack.deprovision`/`archive!` executed for `victim-org/prod-repo` despite the request being authenticated only against `attacker-org`'s secret.

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

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L49-57)
```ruby
          def handle
            if archive?
              stack.archive!
            elsif unarchive?
              stack.unarchive!
            end

            stack
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L23-35)
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
```

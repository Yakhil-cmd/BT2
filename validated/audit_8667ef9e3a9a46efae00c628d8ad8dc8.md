The finding is valid. I have sufficient evidence to construct the full trace.

**Binding claimed:** `signing_org` (the org whose `webhook_secret` produced a passing `verify_webhook_signature`) `==` `owning_org` (the org whose `Repository#owner` / `review_stacks` get mutated and whose `GITHUB_TOKEN` executes deploy `Command`s).

Trace:
1. `WebhooksController#verify_signature` derives the signing org exclusively from `params.dig('repository', 'owner', 'login')` and verifies the HMAC against that org's `webhook_secret` via `Shipit.github(organization: repository_owner)`. [1](#0-0) [2](#0-1) 
2. `Shipit::Webhooks::Handlers::PullRequest::OpenedHandler#repository` never reads `repository.owner.login`; it resolves the target repository solely from `params.repository.full_name`. [3](#0-2) 
3. The `params` schema for `OpenedHandler` only requires `repository.full_name`, never `repository.owner.login`, so nothing forces these two fields to agree. [4](#0-3) 
4. `Repository.from_github_repo_name` parses owner/name purely from the string `full_name`, independent of any signature-verified org. [5](#0-4) 
5. `provision?` for `prevent_with_label` behavior is satisfied by simply omitting the provisioning label — attacker-controlled. [6](#0-5) 
6. `ReviewStackAdapter#find_or_create!`/`#create!` then creates a `Stack` scoped to `repository.review_stacks` (the victim repo resolved in step 3-4), sets `branch: params.pull_request.head.ref` (attacker-controlled) and enqueues it via `ReviewStackProvisioningQueue.add(stack)`. [7](#0-6) 
7. Documentation confirms multi-org Shipit deployments are a first-class supported configuration, each org with its own `webhook_secret`/GitHub App credentials — i.e. it is expected that multiple independently-administered GitHub orgs share one Shipit instance and each org admin legitimately knows their own org's `webhook_secret`. [8](#0-7) 
8. Subsequent deploy/provisioning `Command`/GitHub API calls for the created stack use `Repository#github_app`, which is `Shipit.github(organization: owner)` — resolved from the victim repo's own `owner` column, meaning the *victim's* GitHub App/installation token (`GITHUB_TOKEN`) is what actually executes, not the attacker's. [9](#0-8) 

Exploit: An org admin/attacker who legitimately administers "OrgOne" (a separate, real org onboarded onto the shared multi-tenant Shipit instance) knows OrgOne's `webhook_secret`. They POST to `/webhooks` with `X-Github-Event: pull_request`, a valid `X-Hub-Signature` computed with OrgOne's secret, and a JSON body where `repository.owner.login = "OrgOne"` (used only for signature-org lookup) but `repository.full_name = "OrgTwo/victim-repo"` (used by `OpenedHandler` to resolve and mutate the target). No label is attached to the PR. If `OrgTwo/victim-repo` has `provisioning_behavior_prevent_with_label`, `provision?` returns true, and a live `ReviewStack` is created/queued for provisioning against the victim's repo, using the victim's own GitHub App credentials for subsequent `Command`/`PTY.spawn` deploy execution.

None of the existing guards catch this: `verify_signature` only checks that *some* known org's secret matches the signature — it never checks that this org is the one whose data (`repository.full_name`) is being acted upon. `drop_unhandled_event`, `ExplicitParameters` schema and `Repository` format validators don't cross-check `owner.login` against `full_name` either.

### Title
Webhook signature verification org is decoupled from the repository resolved by `PullRequest::OpenedHandler`, enabling cross-tenant review-stack provisioning - (File: app/controllers/shipit/webhooks_controller.rb, app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb)

### Summary
`WebhooksController#verify_signature` authenticates a webhook payload using the org named in `repository.owner.login`, but `PullRequest::OpenedHandler` (and its sibling handlers) resolve the actual target `Repository`/`review_stacks` from the independent `repository.full_name` field of the same JSON body. In Shipit's documented multi-org configuration, an admin of one onboarded org can sign a payload with their own valid `webhook_secret` while setting `full_name` to point at a different onboarded org's repository, causing a `ReviewStack` to be provisioned (and deploy `Command`s eventually executed with the victim org's `GITHUB_TOKEN`) for a repository the signing org never authenticated.

### Finding Description
Broken binding: `signing_org (params.repository.owner.login, verified against its webhook_secret)` should equal `owning_org (owner of params.repository.full_name → Repository#owner, review_stacks, github_app)`, but no code enforces this equality.

`verify_signature` computes `repository_owner` from `params.dig('repository', 'owner', 'login')` and verifies the HMAC signature using `Shipit.github(organization: repository_owner)` [10](#0-9) . `OpenedHandler#repository`, however, resolves the repository purely from `params.repository.full_name` via `Repository.from_github_repo_name` [3](#0-2) [5](#0-4) , and the `ExplicitParameters` schema never requires `repository.owner.login` to be present, let alone consistent with `full_name` [4](#0-3) . Since Shipit natively supports hosting multiple independently administered GitHub organizations behind one instance, each with its own `webhook_secret` [8](#0-7) , an admin of "OrgOne" can send a raw `POST /webhooks` request they sign themselves (they legitimately know OrgOne's secret) with `repository.owner.login = "OrgOne"` but `repository.full_name = "OrgTwo/victim-repo"`. This passes signature verification, then `provision?` is satisfied trivially by omitting the provisioning label on a `prevent_with_label`-configured victim repo [6](#0-5) , and `ReviewStackAdapter#create!` writes a new `Stack` into `repository.review_stacks` (the victim's) with attacker-controlled `branch`, then enqueues it for provisioning [7](#0-6) . Provisioning/deploy commands subsequently run under the victim's own GitHub App/installation credentials because `Repository#github_app` is derived from the resolved repo's own `owner` column [9](#0-8) .

### Impact Explanation
A write (new `Stack`/`ReviewStack`, `PullRequest` record) is created for a repository belonging to an org that never authenticated the request, and that record is queued for provisioning which runs `Command`/`PTY.spawn`-based deploy tasks using the victim org's `GITHUB_TOKEN`. This matches the Critical category "a payload for one repository mutating another's stack ... or an unauthorized deploy." It is repeatable against any repository tracked by any other onboarded org in the same multi-tenant Shipit instance, and the branch/environment of the forged stack is fully attacker-controlled.

### Likelihood Explanation
Requires a Shipit deployment configured with multiple GitHub organizations (a documented, supported configuration) and requires the attacker to legitimately administer at least one onboarded org (so they know its `webhook_secret`) while the victim repository uses `provisioning_behavior_prevent_with_label`. Given these preconditions, the attack is a single crafted HTTP POST with no other authentication artifacts needed, fully repeatable.

### Recommendation
In `WebhooksController#verify_signature`, require and validate that `params.dig('repository','owner','login')` matches the owner segment parsed from `params.dig('repository','full_name')` (reject on mismatch), or better, have every handler resolve/authorize the repository using the same org identity that signed the request rather than trusting `full_name` independently.

### Proof of Concept
minitest plan (`test/controllers/webhooks_controller_test.rb` or a new test using `test/dummy/config/secrets_double_github_app.yml`):
1. Load `secrets_double_github_app.yml` fixtures registering `OrgOne` and `OrgTwo`; create `Shipit::Repository` `OrgTwo/victim-repo` with `review_stacks_enabled: true`, `provisioning_behavior: :prevent_with_label`.
2. Build a `pull_request` "opened" payload with `repository: { owner: { login: "OrgOne" }, full_name: "OrgTwo/victim-repo" }`, no labels on the PR.
3. Compute `X-Hub-Signature` using `OrgOne`'s configured `webhook_secret` (`Hook::DeliverySigner`-style HMAC-SHA1 over the raw body).
4. `post :create` with that body/signature/`X-Github-Event: pull_request`; assert `response.status == 200` (signature accepted).
5. Assert `OrgTwo/victim-repo`.review_stacks.count` increased by 1 — proving `signing_org("OrgOne") != owning_org("OrgTwo")` yet the write succeeded.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-62)
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

    def check_if_ping
      head(:ok) if event == 'ping'
    end

    def event
      request.headers.fetch('X-Github-Event')
    end

    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L33-35)
```ruby
            requires :repository do
              requires :full_name, String
            end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L65-74)
```ruby
          def provision?
            repository.review_stacks_enabled &&
              repository.provisioning_behavior_allow_all? ||
              (repository.provisioning_behavior_allow_with_label? && pull_request_has_provisioning_label?) ||
              (repository.provisioning_behavior_prevent_with_label? && !pull_request_has_provisioning_label?)
          end

          def pull_request_has_provisioning_label?
            pull_request_label_names.include?(repository.provisioning_label_name)
          end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/repository.rb (L98-102)
```ruby
    protected

    def github_app
      Shipit.github(organization: owner)
    end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-94)
```ruby
          def create!
            ReviewStack.transaction do
              stack = scope.create!(stack_attributes)
              stack
                .build_pull_request
                .update!(
                  github_pull_request: params.pull_request
                )
            end

            Shipit::ReviewStackProvisioningQueue.add(stack)

            @stack = stack
          end

          def stack_attributes
            {
              branch: params.pull_request.head.ref,
              environment:,
              ignore_ci: false,
              continuous_deployment: false
            }
          end
```

**File:** docs/setup.md (L182-209)
```markdown
### Using Multiple Github Applications

A Github application can only authenticate to the Github organization it's installed in. If you want to deploy code from multiple Github organizations the `github` section of your `config/secrets.yml` will need to be formatted differently. The top-level keys should be the name of each Github organization, and the following sub-keys are the Github app details for that particular organization.

For example:

```yml
production:
  github:
    somegithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
    someothergithuborg:
      app_id:
      installation_id:
      webhook_secret:
      private_key:
      oauth:
        id:
        secret:
        teams:
```
```

## Finding

### Title
Webhook signature is verified against the `repository.owner.login` field while stack/repository lookup uses the unrelated `repository.full_name` field, letting an attacker authenticated for one GitHub organization trigger review-stack provisioning/archival on any other organization's stacks - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects which GitHub App config (and thus which HMAC secret) to verify the inbound webhook against using `repository_owner`, computed from the payload's `repository.owner.login` field [1](#0-0) [2](#0-1) . Once the signature is accepted, every downstream `Handler` resolves the actual target repository/stack using a *different* field, `repository.full_name`, via `Handler#repository_name` / `Repository.from_github_repo_name` [3](#0-2) [4](#0-3) . Nothing cross-checks that `repository.owner.login` is actually the owner prefix of `repository.full_name`.

Because Shipit supports multiple GitHub Apps/organizations configured under distinct top-level keys with independent `webhook_secret`s [5](#0-4) [6](#0-5) , an attacker who legitimately installed a Shipit-integrated GitHub App on their own organization "OrgB" (and thus knows OrgB's `webhook_secret`) can craft a `pull_request` payload where `repository.owner.login` = `"OrgB"` (so `verify_signature` loads and validates against OrgB's secret, which the attacker controls) but `repository.full_name` = `"Shopify/some-other-repo"` (an unrelated, victim organization's repository also hosted on the same Shipit instance).

### Finding Description
This is the same trust-binding break as the reported bug class: a field used to authenticate/authorize an action (`repository.owner.login`, used to pick the GitHub App whose secret verifies the signature) is not the same field that is acted upon (`repository.full_name`, used to resolve the `Repository`/`Stack`/`ReviewStack` that gets mutated). The equality that should hold but doesn't is:

`organization that authenticated (repository.owner.login → secret used) == repository that is written (repository.full_name → Stack/ReviewStack resolved)`

`PullRequest::OpenedHandler`, `ClosedHandler`, `LabeledHandler`, `UnlabeledHandler`, and `ReopenedHandler` all resolve `repository` purely from `params.repository.full_name` [7](#0-6) [8](#0-7) , then act via `ReviewStackAdapter`, which creates or archives a `ReviewStack` and enqueues it onto `ReviewStackProvisioningQueue` [9](#0-8) [10](#0-9) . Provisioning a review stack runs the target repository's real `shipit.yml` provisioning steps on the deploy host using that repository's own GitHub App credentials — i.e., it is a genuine cross-repository, unauthorized deploy/provision action, not merely a metadata change.

### Impact Explanation
An attacker who only controls one organization's GitHub App installation (and its webhook secret) can pass signature verification and then force Shipit to create, archive, or unarchive review stacks for a completely different, victim organization's repository that happens to be configured on the same Shipit instance. Review stack creation triggers real provisioning (deploy task execution) on the deploy host against the victim repository, which matches the "cross-repository writes" / "unauthorized deploy" Critical impact category.

### Likelihood Explanation
Requires the attacker to control (or be a member of) at least one GitHub organization/App configured on the same Shipit deployment as the victim organization — a realistic scenario for any Shipit instance hosting multiple orgs/apps as documented in "Using Multiple Github Applications" [5](#0-4) . No other privileged credential (API client token, GitHub App private key, session) is needed beyond the attacker's own legitimately-configured org's webhook secret.

### Recommendation
After `verify_signature` succeeds, re-derive the authorized organization strictly from the verified GitHub App config and require that every handler's target `repository.full_name` owner match that same organization before resolving/acting on any `Repository`/`Stack`/`ReviewStack`. Reject the webhook (422) if `repository.owner.login` (or `organization.login`) does not match the owner segment of `repository.full_name`.

### Proof of Concept
1. Shipit is configured with two orgs, e.g. `OrgB` (attacker-controlled GitHub App, attacker knows `webhook_secret_B`) and `Shopify` (victim org, has repo `Shopify/some-other-repo` with review stacks enabled), per the multi-org config format [11](#0-10) .
2. Attacker builds a `pull_request` "opened" webhook body:
```json
{
  "action": "opened",
  "number": 999,
  "pull_request": { "head": { "ref": "attacker-branch" }, ... },
  "repository": { "owner": { "login": "OrgB" }, "full_name": "Shopify/some-other-repo" },
  "sender": { "login": "attacker" }
}
```
3. Attacker signs the raw body with `webhook_secret_B` (their own known secret) and sets `X-Hub-Signature` accordingly, `X-Github-Event: pull_request`.
4. `WebhooksController#verify_signature` computes `repository_owner = "OrgB"`, loads `Shipit.github(organization: "OrgB")`, and verification succeeds because the attacker used OrgB's own secret [1](#0-0) .
5. `PullRequest::OpenedHandler#process` resolves `repository = Repository.from_github_repo_name("Shopify/some-other-repo")` (a real DB lookup unrelated to OrgB) and calls `ReviewStackAdapter#find_or_create!`, provisioning a review stack for `Shopify/some-other-repo` [12](#0-11) , despite the attacker never being authenticated for, or granted access to, the `Shopify` organization.

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L41-54)
```ruby
          def process
            return unless respond_to_pull_request_opened?

            Shipit::Webhooks::Handlers::PullRequest::ReviewStackAdapter
              .new(params, scope: repository.review_stacks).find_or_create!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/labeled_handler.rb (L65-68)
```ruby
          def repository
            @repository ||= Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
                            Shipit::NullRepository.new
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

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L72-85)
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
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-20)
```yaml
  github:
    OrgOne:
      domain: # defaults to github.com
      app_id: 42
      installation_id: 43
      bot_login: "shipit[bot]"
      webhook_secret: # nil
      # Randomly generated
      private_key: |
        -----BEGIN RSA PRIVATE KEY-----
        MIIEpAIBAAKCAQEA7iUQC2uUq/gtQg0gxtyaccuicYgmq1LUr1mOWbmwM1Cv63+S
        73qo8h87FX+YyclY5fZF6SMXIys02JOkImGgbnvEOLcHnImCYrWs03msOzEIO/pG
        M0YedAPtQ2MEiLIu4y8htosVxeqfEOPiq9kQgFxNKyETzjdIA9q1md8sofuJUmPv
        ibacW1PecuAMnn+P8qf0XIDp7uh6noB751KvhCaCNTAPtVE9NZ18OmNG9GOyX/pu
        pQHIrPgTpTG6KlAe3r6LWvemzwsMtuRGU+K+KhK9dFIlSE+v9rA32KScO8efOh6s
        Gu3rWorV4iDu14U62rzEfdzzc63YL94sUbZxbwIDAQABAoIBADLJ8r8MxZtbhYN1
        u0zOFZ45WL6v09dsBfITvnlCUeLPzYUDIzoxxcBFittN6C744x3ARS6wjimw+EdM
        TZALlCSb/sA9wMDQzt7wchhz9Zh2H5RzDu+2f54sjDh38KqancdT8PO2fAFGxX/b
        qicOVyeZB9gv6MJtJc20olBbuXAeBNfcDABF9oxF+0i+Ssg7B4VXiqgcjtGbr/Og
        qRll7AqyTArVx2xEcVfZxeZ4zGnigzcJq4te7yYpxzwk+RxblkPh54Yt4WxZ+8DI
```

Confirmed: the review-stack provisioning path (`OpenedHandler#process` → `ReviewStackAdapter#find_or_create!`/`#unarchive!` → `ReviewStackProvisioningQueue.add` → `stack.provision`) queues a real deploy/provision job driven purely by `params.repository.full_name`, with no re-check against the organization whose webhook secret validated the request.

### Title
Cross-tenant unauthorized stack provisioning/deploy via organization/repository binding break in webhook signature verification - (File: `app/controllers/shipit/webhooks_controller.rb`)

### Summary
`WebhooksController#verify_signature` selects the GitHub App (and therefore the HMAC secret) to validate an inbound webhook against using `repository_owner`, computed as `params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')`. [1](#0-0)  Once the signature check passes, `create` dispatches the *entire, attacker-controlled* JSON body to the matching event handlers. [2](#0-1)  Every handler, however, resolves the target `Repository`/`Stack` independently, using `payload.dig('repository', 'full_name')` — a different field of the same signed body. [3](#0-2)  Nothing ties the field used to pick the verifying secret (`repository.owner.login`) to the field used to pick the acted-upon resource (`repository.full_name`). In Shipit's documented multi-organization mode, each organization has its own GitHub App and its own `webhook_secret` configured under a distinct top-level key in `secrets.yml`. [4](#0-3) [5](#0-4) 

### Finding Description
The equality that should hold is: *organization whose secret authenticated the request == owner of the repository that the handler subsequently acts on*. This binding is broken because the two values are read from independent, attacker-suppliable JSON keys within the same signed payload, and nothing cross-validates them.

- `verify_signature` picks the verifying `GitHubApp`/secret via `repository_owner` (`repository.owner.login`, or `organization.login` as fallback). [1](#0-0)  `Shipit.github(organization:)` selects the per-org config (webhook_secret, keys) from `secrets.github[organization]`. [6](#0-5) 
- Handlers ignore `repository.owner` entirely and instead resolve their target using `repository.full_name`: `Repository.from_github_repo_name(repository_name)`, `repository_name = payload.dig('repository', 'full_name')`. [3](#0-2) 
- For pull-request events, `OpenedHandler`/`ReopenedHandler`/`LabeledHandler`/`UnlabeledHandler` use `Repository.from_github_repo_name(params.repository.full_name)` to find the repository whose `review_stacks` scope is used to find-or-create/unarchive a `ReviewStack`, which is then queued for provisioning: `ReviewStackProvisioningQueue.add(stack)` → `stack.enqueue_for_provisioning` → later `stack.provision`. [7](#0-6) [8](#0-7) [9](#0-8) 

Since `repository.owner.login` and `repository.full_name` are two independent fields inside the *same* attacker-authored JSON body that is HMAC-signed as a whole, an entity that legitimately possesses the `webhook_secret` for its own configured organization (e.g. the admin who created and registered that organization's GitHub App, as documented in the multi-org setup flow) can produce a validly-signed payload where:
- `repository.owner.login` = their own organization ("OrgA") → passes `verify_signature`, since that org's real secret is used to compute a correct HMAC.
- `repository.full_name` = an arbitrary *other* organization's repository ("OrgB/some-repo") already onboarded as a Stack in the same Shipit instance.

The handler layer never re-derives or re-checks the authenticated organization; it trusts `repository.full_name` unconditionally to look up the `Repository`/`Stack` to act on.

### Impact Explanation
This breaks the tenant isolation that the multi-organization webhook_secret design is meant to provide: authentication as OrgA is accepted as authorization to act on OrgB's onboarded repository/stack. Concretely, an attacker authenticated only as OrgA can:
- Trigger `GithubSyncJob`/`stack.sync_github` for OrgB's stack. [10](#0-9) 
- Force creation/unarchival of a `ReviewStack` under OrgB's repository and enqueue it for provisioning, which results in real deploy steps being executed against OrgB's environment via `stack.provision` — an unauthorized deploy/cross-repository write on infrastructure the attacker does not own. [8](#0-7) 
- Archive/deprovision OrgB's review stacks via the closed/unlabeled handlers, disrupting OrgB's deployments.

This matches the Critical "cross-repository writes" / "unauthorized deploy" category: an attacker who only controls their own tenant's webhook credentials can cause state-changing operations (sync, provision, deploy, archive) on a different tenant's repository/stack.

### Likelihood Explanation
Exploitability requires the Shipit instance to be running in the documented multi-organization configuration with more than one organization's `webhook_secret` configured, and requires the attacker to possess a valid `webhook_secret` for at least one configured organization (which, per the documented setup flow, is created and known by whoever registers that organization's GitHub App). No access to Shipit's admin UI, `ApiClient` tokens, or the target organization's own credentials is required — only the ability to POST a signed payload to the shared `/github/webhooks` endpoint with a `repository.full_name` field pointing at another tenant's repository. This is a realistic multi-tenant threat model directly enabled by the feature described in `docs/setup.md`'s "Using Multiple Github Applications" section. [5](#0-4) 

### Recommendation
After signature verification resolves the authenticated organization (`repository_owner`), re-validate downstream that the `repository.full_name` (or any other repository identifier consumed by handlers) belongs to that same authenticated organization before dispatching to handlers — e.g., reject/short-circuit in `WebhooksController#create` if `params.dig('repository','full_name')&.split('/')&.first` does not case-insensitively match the `repository_owner` used for signature verification, or thread the authenticated organization through to `Repository.from_github_repo_name` lookups so cross-organization repositories are never resolved from an unrelated org's signed webhook.

### Proof of Concept
1. Configure Shipit with two organizations in `secrets.yml`, each with its own `webhook_secret` (as in `test/dummy/config/secrets_double_github_app.yml`). [11](#0-10) 
2. Onboard `OrgB/target-repo` as a `Repository` with an associated `Stack` and `review_stacks_enabled` (attacker does not need any access to OrgB).
3. As an entity that legitimately knows OrgA's `webhook_secret`, craft a `pull_request` `opened` event JSON body where `repository.owner.login = "OrgA"` and `repository.full_name = "OrgB/target-repo"`, and compute `X-Hub-Signature: sha1=HMAC(orgA_secret, raw_body)`.
4. POST to `/github/webhooks` with `X-Github-Event: pull_request`. `verify_signature` resolves `repository_owner` to `"OrgA"`, fetches OrgA's `GitHubApp`, and the signature validates successfully. [12](#0-11) 
5. `OpenedHandler#process` resolves the repository via `Repository.from_github_repo_name(params.repository.full_name)` → `OrgB/target-repo`, and (subject to `review_stacks_enabled`/`provisioning_behavior`) creates/unarchives a `ReviewStack` and enqueues it for provisioning. [7](#0-6) [8](#0-7) 
6. The provisioning worker subsequently runs `stack.provision`, executing real deploy steps against OrgB's environment — a deploy the attacker never had authorization to trigger.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** lib/shipit/github_app.rb (L44-57)
```ruby
    def initialize(organization, config)
      super()
      @mutex = Mutex.new
      @organization = organization
      @config = (config || {}).with_indifferent_access
      @domain = @config[:domain] || DOMAIN
      @webhook_secret = @config[:webhook_secret].presence
      @bot_login = @config[:bot_login]

      oauth = (@config[:oauth] || {}).with_indifferent_access
      @oauth_id = oauth[:id]
      @oauth_secret = oauth[:secret]
      @oauth_teams = Array.wrap(oauth[:teams])
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

**File:** app/models/shipit/review_stack_provisioning_queue.rb (L9-19)
```ruby
    def self.add(stack)
      stack.enqueue_for_provisioning
    end

    def self.queued_stacks
      new.queued_stacks
    end

    def work
      queued_stacks.find_each(&method(:provision))
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L12-17)
```ruby
        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
        end
```

**File:** test/dummy/config/secrets_double_github_app.yml (L1-41)
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
        Rsn3r6ajlpwzpwvsJFU2Txq7xBTzGQMFmy/Pnjk83kP2cogxB2+tRyjITGqTwD8b
        gg9PFCkCgYEA+7u8A0l0Cz6p0SI6c7ftVePVRiIhpawWN7og/wEmI6zUjm/3rA+R
        hrhaVKuOD8QF/HdDsqTck5gjGAjTmJz6r33/cl1Tz+pr62znsrB4r0yMKvQbKN81
        WGaWOsi2+ZXqLNv5h5wpUF0MTKlXHeKnwP5kuEvGwVn6WURFCh6PhLMCgYEA8i5e
        JjulJVGyd5HuoY3xyO7E6DjidsqRnVRq+hYpORjnHvTmSwe4+tH4ha2p9Kv2Y6k3
        C1NYY/fSMQoYCCRaYyJleI+la/9tsZqAmtms4ZB8KhFmPHf9fW75i6G0xKWyZ8K+
        E2Ft/UaEiM282593cguV6+Kt5uExnyPxLLK4FlUCgYEAwRJ/JGI8/7bjFkTTYheq
        j5q75BufhOrU6471acAe2XPgXxLfefdC3Xodxh0CS3NESBvNL4Ikr4sbN37lk4Kq
        /th7iOKtuqUIeru/hZy2I3VpeDRbdGCmEJQ2GwYA2LKztg5Nd0Y9paaIHXAwIfrK
        QUqcQ4HTAk8ZpUeoUBeaaeMCgYANLmbjb9WiPVsYVPIHCwHA7PX8qbPxwT7BsGmO
        KQyfVfKmZa/vH4F67Vi4deZNMdrcO8aKMEQcVM2065a5QrlEsgeR00eupB1lUEJ1
        qylUsZeAdqf43JMIc7TTW77KATa/nQLZbTEeWus1wvTngztuEqFbUGAks9cOkVc8
        FpIcbQKBgQDVIL8gPLmn0f+4oLF8MBC+oxtKpz14X5iJ1saGFkzW5I+nIEskpS0S
        qtirnTCnJFGdCrFwctnxiuiCmyGwpBYdjIfHyvYAHnqAtMnESzCUyeSFZiquVW5W
        MvbMmDPoV27XOHU9kIq6NXtfrkpufiyo6/VEYWozXalxKLNuqLYfPQ==
        -----END RSA PRIVATE KEY-----
      oauth:
        id: Iv1.bf2c2c45b449bfd9
        secret: ef694cd6e45223075d78d138ef014049052665f1
        teams:
    OrgTwo:
```

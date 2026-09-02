### Title
Webhook signature is verified against the org derived from `repository.owner.login`, but every event handler acts on the repository named in the independent, unverified `repository.full_name` field, enabling cross-organization webhook forgery - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController` picks which GitHub App / `webhook_secret` to verify the inbound signature against using `repository.owner.login` (or `organization.login`) taken straight from the untrusted JSON body, while every `Handler` subclass resolves the `Stack`/`Repository` to actually mutate using a *different* untrusted field from the same body, `repository.full_name`. Nothing binds these two fields together, so a signature that is valid for organization A's webhook secret can carry a payload whose `repository.full_name` names a repository belonging to organization B.

### Finding Description
`verify_signature` computes the organization to authenticate against purely from payload content: [1](#0-0) [2](#0-1) 

`repository_owner` reads `params.dig('repository', 'owner', 'login')`, and `Shipit.github(organization: repository_owner)` selects the app config (and thus the `webhook_secret` used for HMAC verification) for that organization only. If verification succeeds, `create` dispatches the **entire raw `params` hash**, unmodified, to every registered handler for the event: [3](#0-2) 

Handlers never re-check `repository.owner.login`. Instead, the base `Handler` class resolves the target `Repository`/`Stack` using a completely separate field, `repository.full_name`: [4](#0-3) 

`Repository.from_github_repo_name` simply splits this string on `/` and looks it up with no relationship enforced back to `repository.owner.login`: [5](#0-4) 

Concrete handlers such as `PushHandler` (which triggers `stack.sync_github`) and `PullRequest::LabelCapturingHandler` (which resolves `repository`/`stack` again from `params.repository.full_name` and mutates PR label state used for deploy-safety gating) both operate purely on that field: [6](#0-5) [7](#0-6) 

In a single-organization Shipit deployment this discrepancy is latent because `repository.owner.login` and the owner segment of `repository.full_name` are normally the same GitHub org anyway. It becomes an exploitable trust-binding break in the documented multi-organization configuration, where distinct GitHub Apps (and distinct `webhook_secret`s) are configured per organization: [8](#0-7) 

An attacker who controls (or can trigger real deliveries from) one configured organization's GitHub App — e.g., they administer "attacker-org", which is one of the organizations legitimately onboarded to the same Shipit instance — knows or can obtain a validly-signed webhook body for `repository.owner.login = "attacker-org"`. They can then craft (or intercept-and-modify before delivery is impossible, but can freely construct their own POST since the endpoint is a public webhook receiver) a payload where:
- `repository.owner.login` = `"attacker-org"` → used only for signature/app selection, passes `verify_signature` using attacker-org's own known secret.
- `repository.full_name` = `"victim-org/victim-repo"` → used by every handler to locate and mutate the real target `Stack`/`Repository`.

Because the controller signs/authenticates on one field and every handler acts on a different, unrelated field of the same untrusted body, the binding "organization that authenticated" ≠ "repository that is written" is violated.

### Impact Explanation
This allows an attacker who is not privileged on `victim-org` to forge `push`, `pull_request`, `status`, and `check_suite` events against `victim-org`'s stacks:
- `PushHandler` calls `stack.sync_github(expected_head_sha:)`, forcing an out-of-band commit sync for a victim stack.
- `PullRequest::LabelCapturingHandler` and sibling handlers (`opened_handler`, `labeled_handler`, `unlabeled_handler`, `reopened_handler`, `closed_handler`) mutate PR label/state data used to drive review-stack provisioning and deploy safety checks for the victim organization's stacks.

This is a cross-repository/cross-organization write performed without any credential belonging to the victim organization, directly matching the required "cross-repository writes" high/critical impact criterion, since the attacker only needs standing as an authenticated org in the same Shipit instance (not repository write access or an API token to the victim repo).

### Likelihood Explanation
Requires: (a) a multi-organization Shipit deployment (documented, supported configuration), and (b) the attacker controls a webhook-eligible relationship with at least one of the configured organizations (i.e., can generate validly-signed deliveries for their own org, which any org admin who installed their own GitHub App naturally can). No access to the victim's secrets, tokens, or GitHub App is required. The likelihood is moderate — it depends on multi-org deployment being in use, but requires no privileged victim-side credential.

### Recommendation
Bind the field used to select the verifying organization to the field used to resolve the acted-upon repository. Concretely:
- In `WebhooksController#verify_signature`, derive `repository_owner` from `repository.full_name`'s owner segment (or validate that `repository.owner.login` equals the owner parsed from `repository.full_name`) before selecting the GitHub App/secret.
- In `Handler#repository_name` / `Repository.from_github_repo_name`, reject or ignore payloads where `repository.full_name`'s owner does not match the organization whose secret validated the signature.
- Alternatively, look up the `Repository`/`Stack` and re-derive the expected signing organization from the resolved repository's own `owner` column, rather than trusting any organization-identifying field taken from the request body.

### Proof of Concept
1. Deploy Shipit with two organizations configured under `github:` (`attacker-org` and `victim-org`), each with its own `webhook_secret`, per the documented multi-org setup (`docs/setup.md` lines 181-209).
2. As the administrator/owner of `attacker-org`, obtain (or self-compute, since the secret is known to the org admin) a valid `X-Hub-Signature` for a JSON body containing:
   ```json
   {
     "repository": { "owner": { "login": "attacker-org" }, "full_name": "victim-org/victim-repo" },
     "ref": "refs/heads/master",
     "after": "<attacker-chosen sha>"
   }
   ```
3. POST this to `/github/webhooks` with `X-Github-Event: push` and the signature computed with `attacker-org`'s `webhook_secret`.
4. `WebhooksController#verify_signature` calls `Shipit.github(organization: 'attacker-org')` and successfully verifies the signature against `attacker-org`'s secret (`app/controllers/shipit/webhooks_controller.rb:24-30`).
5. `Webhooks::for_event('push')` dispatches to `PushHandler`, whose `stacks` method resolves `Repository.from_github_repo_name('victim-org/victim-repo')` (`app/models/shipit/webhooks/handlers/handler.rb:32-38`, `app/models/shipit/repository.rb:53-56`) and calls `stack.sync_github(expected_head_sha: "<attacker-chosen sha>")` on a stack owned by `victim-org`, despite the request never being authenticated by anything belonging to `victim-org`.

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

**File:** app/controllers/shipit/webhooks_controller.rb (L59-62)
```ruby
    def repository_owner
      # Fallback to the organization sub-object if repository isn't included in the payload
      params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
    end
```

**File:** app/models/shipit/webhooks/handlers/handler.rb (L30-39)
```ruby
        private

        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
      end
```

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
    end
```

**File:** app/models/shipit/webhooks/handlers/push_handler.rb (L6-17)
```ruby
      class PushHandler < Handler
        params do
          requires :ref
          requires :after
        end

        def process
          stacks
            .not_archived
            .where(branch:)
            .find_each { |stack| stack.sync_github(expected_head_sha: params.after) }
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

**File:** docs/setup.md (L181-209)
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

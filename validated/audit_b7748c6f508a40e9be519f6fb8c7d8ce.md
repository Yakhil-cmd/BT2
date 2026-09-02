### Title
Webhook signature verified against a different organization than the one whose repository is mutated (repository_owner vs repository.full_name confusion) - (File: app/controllers/shipit/webhooks_controller.rb)

### Summary
`WebhooksController#verify_signature` selects the HMAC secret to validate an incoming webhook using `repository_owner`, a value read from the attacker-suppliable JSON body (`repository.owner.login` or `organization.login`) [1](#0-0) . Once the signature check passes, the same raw, attacker-controlled body is dispatched to event handlers that instead key their side effects off `repository.full_name`, a separate field of the same body [2](#0-1) . Nothing in the controller or in `Handler` enforces that `repository.owner.login` and the owner segment of `repository.full_name` refer to the same organization/repository. This is the same class of bug as the reported TOCTOU: one identifier is used to authenticate/authorize a request, while a different, unchecked identifier drawn from the same attacker-influenced payload is used to perform the actual state-changing operation.

### Finding Description
`verify_signature` picks the GitHub App/secret to verify against with:
```ruby
def verify_signature
  github_app = Shipit.github(organization: repository_owner)
  verified = github_app.verify_webhook_signature(request.headers['X-Hub-Signature'], request.raw_post)
  head(422) unless verified
  ...
end

def repository_owner
  params.dig('repository', 'owner', 'login') || params.dig('organization', 'login')
end
``` [3](#0-2) 

`Shipit.github(organization:)` looks up the app config keyed by organization name (Shipit explicitly supports multiple GitHub organizations sharing one instance, each with its own `webhook_secret`), and raises `GithubOrganizationUnknown` if it isn't configured — a scenario the controller explicitly handles [4](#0-3) . This multi-org configuration is a documented, first-class setup, not a deviation from the documented deployment [5](#0-4) .

`verify_webhook_signature` only checks that `HMAC(secret_of[repository_owner], raw_body) == signature`; it never inspects the contents of the body beyond that one field [6](#0-5) . Once verification succeeds, `create` hands the fully-attacker-controlled body to the handlers:
```ruby
def create
  params = JSON.parse(request.raw_post)
  Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }
  head(:ok)
end
``` [7](#0-6) 

Every handler resolves the target repository/stack from a *different* field of the same body:
```ruby
def stacks
  @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
end

def repository_name
  payload.dig('repository', 'full_name')
end
``` [2](#0-1) 

`Repository.from_github_repo_name` splits `owner/name` straight out of that field and looks up the tracked repository by it [8](#0-7) . `PushHandler`, for instance, uses this to enqueue `GithubSyncJob` for every matching, non-archived stack of that repository [9](#0-8) .

**Binding broken:** the engine implicitly assumes `repository_owner` (used to select the verifying secret) `==` owner segment of `repository.full_name` (used to select the mutated repository/stack). Neither the controller nor `Handler` enforces this equality. A party who legitimately controls organization `A` (and therefore its correctly-configured `webhook_secret`) can craft a raw JSON body where `repository.owner.login` = `"A"` (so the HMAC computed with `A`'s secret is valid) while `repository.full_name` = `"B/victim-repo"`, an entirely unrelated, unaffiliated organization/repository that is also tracked by the same Shipit instance.

- Before the attack: for genuine GitHub-issued webhooks, `repository.owner.login` and the owner embedded in `repository.full_name` are always the same value, so the implicit binding holds trivially.
- After the attack: the attacker submits a self-crafted, correctly-signed-for-org-A body whose `repository.full_name` names org B's repository; `verify_signature` passes (secret_of["A"] matches), but `handler.call(params)` operates on org B's `Repository`/`Stack` records.

### Impact Explanation
This allows an attacker who only controls one organization tracked by a shared, multi-org Shipit instance to forge webhook events that mutate/enqueue jobs against a completely different organization's repositories/stacks — a cross-repository write with no repository, API-client, or Shipit-session credential for the victim organization required. Depending on the event type this can:
- Force `GithubSyncJob`/`CacheDeploySpecJob` to run against a victim stack (`PushHandler`) [9](#0-8) .
- Inject forged commit statuses/deploy signals or provision/archive PR review stacks belonging to the victim org via the other `Handler` subclasses that also key off `repository.full_name` (`ReviewStackAdapter`, `OpenedHandler`, etc.) [10](#0-9) [11](#0-10) .

This matches the "cross-repository writes" High/Critical impact bucket: an unprivileged attacker (owning only org A's webhook secret) obtains write-triggering influence over org B's tracked repositories/stacks.

### Likelihood Explanation
Requires the deployment to be configured with more than one GitHub organization sharing one Shipit instance (a documented, supported configuration) and the attacker controlling (or having previously been granted) the webhook secret for at least one of those organizations, e.g. by owning/administering a repository legitimately tracked under org A. No additional privilege (no `ApiClient` token, no Shipit session, no GitHub App private key, no `Shipit.github_teams` membership) is required to hit the public `/github/webhooks` endpoint.

### Recommendation
Enforce the implicit binding explicitly: after computing `repository_owner` and verifying the signature, require that the owner segment of `repository.full_name` (and/or `organization.login`) matches `repository_owner` before dispatching to handlers, or better, have `Handler#repository_name`/`#stacks` reuse the exact identifier that was authenticated (`repository_owner`) rather than re-reading a second, independent field of the untrusted body. Reject the webhook (422) on mismatch.

### Proof of Concept
1. Deploy Shipit configured for two GitHub organizations, `orgA` and `orgB`, each tracked with their own repositories/stacks and each with a distinct `github.webhook_secret` (per `docs/setup.md`'s documented multi-org `secrets.yml` layout).
2. As an attacker who legitimately administers `orgA`'s GitHub App/webhook secret, craft a raw JSON body:
```json
{
  "ref": "refs/heads/master",
  "after": "<attacker-chosen sha>",
  "repository": {
    "owner": { "login": "orgA" },
    "full_name": "orgB/victim-repo"
  }
}
```
3. Compute `X-Hub-Signature: sha1=<HMAC-SHA1(orgA_webhook_secret, raw_body)>` and POST it with header `X-Github-Event: push` to `/github/webhooks`.
4. `verify_signature` resolves `repository_owner` = `"orgA"`, fetches `orgA`'s secret, and the signature validates [12](#0-11) .
5. `PushHandler#stacks` resolves `Repository.from_github_repo_name("orgB/victim-repo")` and enqueues `GithubSyncJob` for `orgB`'s stacks [9](#0-8) , despite the attacker having no credentials for `orgB` whatsoever.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L10-15)
```ruby
    def create
      params = JSON.parse(request.raw_post)
      Shipit::Webhooks.for_event(event).each { |handler| handler.call(params) }

      head(:ok)
    end
```

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

**File:** app/models/shipit/webhooks/handlers/handler.rb (L32-38)
```ruby
        def stacks
          @stacks ||= Repository.from_github_repo_name(repository_name)&.stacks || Stack.none
        end

        def repository_name
          payload.dig('repository', 'full_name')
        end
```

**File:** docs/setup.md (L17-38)
```markdown
1. If you don't have Rails installed, run this command: `gem install rails -v 8.0`
2. Run this command:  `rails _8.0_ new shipit --skip-action-cable --skip-turbolinks --skip-action-mailer --skip-active-storage --skip-webpack-install --skip-action-mailbox --skip-action-text -m https://raw.githubusercontent.com/Shopify/shipit-engine/main/template.rb`

## Creating the GitHub App

Shipit needs a GitHub App to authenticate users, receive Webhooks and access the API.

You can create a new one for your organization at `https://github.com/organizations/<your-org>/settings/apps/new`, or [https://github.com/settings/apps/new](https://github.com/settings/apps/new) for a regular user.

  - Homepage URL: The URL where Shipit will be deployed, e.g. `https://example.com`.
  - User authorization callback URL: It must be set to `<homepage>/github/auth/github/callback`, e.g. `https://example.com/github/auth/github/callback`.
  - Setup URL: Leave it empty.
  - Webhook URL: It must be set to `<homepage>/webhooks`, e.g. `https://example.com/webhooks`.
  - Webhook secret (optional): Fill it with some randomly generated string, and *keep it in clear on the side, you'll need it later*.
  - Repository permissions:
    - Checks: Read & write
    - Commit statuses: Read-only
    - Contents: Read & write (to allow merging)
    - Deployments: Read & write
    - Issues: Read & write (to allow closing related issues on merge)
    - Metadata: Read-only
    - Pull requests: Read & write
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

**File:** app/models/shipit/repository.rb (L53-56)
```ruby
    def self.from_github_repo_name(github_repo_name)
      repo_owner, repo_name = github_repo_name.downcase.split('/')
      find_by(owner: repo_owner, name: repo_name)
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

**File:** app/models/shipit/webhooks/handlers/pull_request/opened_handler.rb (L50-54)
```ruby
          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

**File:** app/models/shipit/webhooks/handlers/pull_request/review_stack_adapter.rb (L15-50)
```ruby
          def stack
            @stack ||= scope.find_by(environment:)
          end

          def find_or_create!
            stack || create!
          end

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

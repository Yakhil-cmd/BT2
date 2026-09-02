### Title
Webhook signature is verified against an organization derived from an untrusted payload field, while the actual write target is a different, unverified `repository.full_name` field - ([File: app/controllers/shipit/webhooks_controller.rb])

### Summary
`WebhooksController#verify_signature` selects which GitHub App/organization's `webhook_secret` to validate the HMAC signature against by reading `repository.owner.login` (or `organization.login`) directly out of the attacker-supplied JSON body, before the signature has been checked. Every downstream event handler, however, resolves the actual `Stack`/`Repository` to mutate using a completely different field of the same unverified body: `repository.full_name`. Because the signature only proves "this body was signed with organization X's secret," and never binds that organization to the `full_name` field the handlers act on, a party who knows the `webhook_secret` for one configured organization can forge a signature that is valid for org X while setting `repository.full_name` to any other org/repo known to Shipit.

### Finding Description
`verify_signature` computes the org used for secret lookup purely from payload content: [1](#0-0) [2](#0-1) 

`Shipit.github(organization: repository_owner)` is looked up via `repository_owner`, and `github_app.verify_webhook_signature` checks the raw request body's signature against that organization's own `webhook_secret`, configured per-org in `secrets.yml` (multi-app support): [3](#0-2) [4](#0-3) 

All the event handlers ignore `repository.owner.login`/`organization.login` entirely and instead resolve which `Stack`/`Repository` to act on using `repository.full_name`, taken from the same unverified JSON body: [5](#0-4) 

e.g. `PullRequest::ClosedHandler#repository` resolves `Shipit::Repository.from_github_repo_name(params.repository.full_name)` and then archives the matching review stack: [6](#0-5) 

The binding that should hold is:
`organization used to select webhook_secret for signature verification == organization owning repository.full_name acted upon by the handler`

Because both values are read from the same attacker-controlled JSON body, and only the first is covered by the cryptographic signature check (indirectly, by selecting which secret is used), nothing forces them to refer to the same organization. This is the direct analog of the audited bug: `CvxLocker.setBoost` validated the already-set storage variable instead of the incoming parameter that is actually applied; here, the controller validates the signature against one payload field (`repository.owner.login`) while the security-relevant action is taken based on a different, never-cross-checked payload field (`repository.full_name`).

### Impact Explanation
An attacker who is a legitimate GitHub App/webhook sender for **one** organization configured in Shipit's multi-org `secrets.yml` (i.e., they know that org's `webhook_secret`, which is routinely handed to GitHub and is not treated as secret from that org's own admins) can craft an arbitrary JSON payload, sign it with their own organization's `webhook_secret`, and set `repository.full_name` to point at a Stack belonging to a completely different organization hosted on the same Shipit instance. This satisfies the "organization that authenticated versus the repository that is written" analog and results in cross-repository state changes: e.g. forcing `PullRequest::ClosedHandler` to archive review stacks, `push` events to enqueue `GithubSyncJob` for arbitrary stacks (fetching commits and mutating commit/lock state), or membership/team webhooks creating spurious teams/users — all scoped to a repository the attacker was never authorized to touch. This is a cross-repository write achieved without any Shipit session, API token, or repository access on the target repo, satisfying the High/Critical impact bar (cross-repository writes / unauthorized state changes triggered on stacks outside the attacker's own organization).

### Likelihood Explanation
Exploitability requires only that the attacker is a valid webhook sender for at least one organization configured on the shared Shipit instance (the documented multi-org setup in `docs/setup.md`), which is a low-privilege, externally-facing capability (anyone who can trigger GitHub App webhooks for their own org, e.g., an org admin who installed the app on a repo they control). No `ApiClient` token, GitHub App private key, or Shipit session is required — only the ability to compute an HMAC-SHA1 over an arbitrary body with a `webhook_secret` value they legitimately possess and POST it to the public `/webhooks` endpoint.

### Recommendation
After verifying the signature, cross-check that the organization used to select the `webhook_secret` (`repository.owner.login` / `organization.login`) matches the organization embedded in `repository.full_name` before dispatching to handlers; reject the request if they diverge. Alternatively, resolve the target `Repository`/`Stack` using the same verified organization identifier used for signature selection rather than trusting `full_name` independently.

### Proof of Concept
1. Shipit is configured with two GitHub orgs, `OrgA` and `OrgB`, each with its own `webhook_secret` (per `docs/setup.md`'s "Using Multiple Github Applications" section).
2. Attacker legitimately controls a repo under `OrgA` and thus knows/can obtain `OrgA`'s `webhook_secret` (delivered to GitHub's webhook configuration for `OrgA`).
3. Attacker crafts a `pull_request` "closed" payload with:
   - `organization.login` / `repository.owner.login` = `"OrgA"`
   - `repository.full_name` = `"OrgB/victim-repo"` (a real Stack on the instance)
4. Attacker computes `X-Hub-Signature: sha1=HMAC(OrgA_webhook_secret, raw_body)` and POSTs to `/webhooks` with `X-Github-Event: pull_request`.
5. `verify_signature` resolves `repository_owner` = `"OrgA"`, fetches `Shipit.github(organization: "OrgA")`, and the signature validates successfully against `raw_body`.
6. `PullRequest::ClosedHandler#process` runs using `params.repository.full_name = "OrgB/victim-repo"`, resolving and archiving the corresponding `OrgB` review stack — a write to a repository the attacker never authenticated for.

### Citations

**File:** app/controllers/shipit/webhooks_controller.rb (L24-31)
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

**File:** lib/shipit/github_app.rb (L76-83)
```ruby
    def verify_webhook_signature(signature, message)
      return true unless webhook_secret

      algorithm, signature = signature.split("=", 2)
      return false unless algorithm == 'sha1'

      SecureCompare.secure_compare(signature, OpenSSL::HMAC.hexdigest(algorithm, webhook_secret, message))
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

**File:** app/models/shipit/webhooks/handlers/pull_request/closed_handler.rb (L41-53)
```ruby
          def process
            return unless respond_to_pull_request_closed?

            review_stack.archive!
          end

          private

          def repository
            @repository ||=
              Shipit::Repository.from_github_repo_name(params.repository.full_name) ||
              Shipit::NullRepository.new
          end
```

### TokaySec
![IMG_1677](https://github.com/user-attachments/assets/b0872f59-55da-4de1-b155-0ecee73e9da3)

TODO...

- [ ] mTLS PostgreSQL database connection. Pretty big for me, please update in the future.

Planned initial features:
- [ ] Zero trust by default
    - [ ] Access roles/groups, project scopes (dev,staging,prod,etc.), advanced user permissions (TBD:add the 
            stuff required to make this work)
- [ ] Multiple auth forms:
    - [ ] By default mTLS for strict security
    - [ ] Allow token based auth (scoped to project, user, roles, etc) on-top 
            or in place of mTLS
    - [ ] Standard oAuth options: google, github, discord, etc. just some common things
    - [ ] Future SSO options and other non-standard sign in options.
    - [ ] Passkeys. **NO PASSWORDS. I DONT GIVE ME A DAMN**
    - [ ] OTP sign-in eitehr via email or phone, but require 2FA (otp alone can be dangerous if person is dumb)
    - [ ] 2FA. Hardware keys, app, TOTP, something else as a second layer.
        - [ ] Possible MFA? who knows. options. options. options.
- [ ] Ability to also store configuration, not just secrets.
- [ ] Ability to store the following secrets:
    - [ ] Keys (some sort of root CA system as well so keys/certs can be requested)
    - [ ] API tokens/keys/string secrets (think stuff like Stripe keys, Twilio, etc.)
    - [ ] SSH keys (make pulling down easy and add some utility to the future CLI to auto-add them
            allow some ssh related config settings so it can just be one command to add ssh keys)
    - [ ] TBD Other keys (suggestions? issue)

raise an issue for more. boilerplate code for now.

### KMS

The provided TokayKMS is ...

### Policies

Roles can be scoped to three levels: instance, namespace and project. When you define a role on a namespace or project level,
the role will automatically have the project/namespace name appended to the start with a `-`. That way, in resulting policies,
you'd reference them such as `<namespace>-<role>`. Instance level roles will **never** have a `<scope name>-` prefix unless manually
defined during creation. 

### Trust

All API requests involving **secrets**, **keys**, or **templated config w/ secrets** must be made with mTLS + appropriate access keys with sufficient permissions to access the secret, project & namespace. The to create secrets, configs, etc. all that is required is an access key with sufficient permissions. Any A2A (application-to-application) requests MUST be made with mTLS, and a access key with sufficient access.

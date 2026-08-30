# Project context

## Glossary

- **User**: A person with an account in this Authserver project.
- **Administrator**: A user allowed to manage users and project authentication settings.
- **Identity provider**: An external service that authenticates a person, such as Google or Facebook.
- **Social identity**: The provider-specific account identity belonging to a user. One user may have multiple social identities.
- **Provider availability**: Whether an identity provider is offered to users of this project.
- **Provider configuration**: The server-owned credentials and connection details required to use an identity provider.
- **End-user choice**: The provider a user selects during sign-in; this does not change their role or permissions.

## Domain decisions

- Administrators control provider availability for the project; end users choose among the available providers.
- Provider credentials are server secrets and are not editable or stored by the admin dashboard.
- A social identity is linked to exactly one local user, and a local user may have multiple social identities.
- Social sign-in never grants administrator privileges based on the provider used.
- Email/password sign-in remains available independently of social-provider availability.

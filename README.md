# Gravito CIAM Client Using DotNet

This is a sample of connecting to IdentityServer using C# project and get the access_token and refresh_token using code flow with PKCE.

Open and view the project using the `.zip` file provided or at my [GitHub Repository]

## Table of Contents
- [Getting started](#getting-started)
- [Tools required](#tools-required)
- [Usage guide](#usage-guide)
- [What after token is expired?](#what-after-token-is-expired)
- [Visit us at](#visit-us-at)

## Getting Started

You can find the detailed documentation about the **Gravito Identity Management** at [Gravito Docs].

We have explained how Gravito works as an Identity Provider.

Here are a few things which helps you consume the Gravito APIs.

## Tools required

* VS Code OR Visual Studio 2019
* Microsoft .Net Core SDK 3.1.*

## Usage guide

We are using OIDC here as we want to connect with IdentityServer using code flow with PKCE:

```c#
services.AddOpenIdConnect("oidc", options =>
{
    options.Authority = Configuration.GetSection("Identity:ServerAddress").Value;
    options.ClientId = Configuration.GetSection("Identity:ClientId").Value;
    options.SaveTokens = true;
    options.ResponseType = "code";
    options.SignedOutCallbackPath = "/Home/Index";
    options.RequireHttpsMetadata = false; // dev only
    options.Prompt = "consent";
    options.ResponseMode = "form_post";
    options.CallbackPath = "/signin-oidc";
    options.UsePkce = true;
});
```
### There are few things we need to understand:

* **ResponseType** is a mandatory request parameter which decides which flow to use. e.g. `token` or `code`.
* **Prompt** is used to show consent page / login page, if required.
It specifies whether the authorization server prompts the user for reauthentication and consent.
* **CallbackPath** after login where to redirect.
* **UsePkce** by default it is `false`, by setting it to `true` we are using PKCE with code flow.

We can access `ServerAddress` and `ClientId` from `appsettings.json` or from Azure Key-Vault.

Detailed documentation can be accessed from [OpenID Documentation] and [IdentityServer OIDC]

How to secure API/Method using OpenID Connect?
Just put an `[Authorize]` attribute before that method.
```c#
using Microsoft.AspNetCore.Authorization;

[Authorize]
public async Task MethodName([parameters])
```

## What after token is expired?
### Here is what you can do:
* As an user, we don't need to do anything. IdentityServer takes care of it.
* Means it sends the `refresh_token` to server and get the new `access_token` along with updated `refresh_token`.


### appsettings.json file
```json
"Identity": {
    "ClientId": "client_id",
    "ServerAddress": "https://your-valid-identityserver-address/"
  }
```

## Visit us at
[Website]

[//]: # (HyperLinks)

[Website]: https://www.gravito.net
[Gravito Docs]: https://docs.gravito.net/gravito-identity-provider/getting-started
[GitHub Repository]: https://github.com/GravitoLtd/gravito-ciam-client-dotnet
[OpenID Documentation]: https://openid.net/developers/specs/
[IdentityServer OIDC]: https://docs.identityserver.io/en/release/quickstarts/3_interactive_login.html

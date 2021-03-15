# Gravito Code Flow .Net Client

This sample demonstrates how to connect with Gravito IdentityServer using C#.Net to get the `access_token` and `refresh_token` using code flow with PKCE.

You can download the zip or clone the repository from [GitHub Repository]

## Table of Contents
- [Getting Started](#getting-started)
- [Tools Required](#tools-required)
- [Usage Guide](#usage-guide)
- [Handling Expired Token](#handling-expired-token)
- [References](#references)
- [Visit Us At](#visit-us-at)

## Getting Started

We have explained how Gravito works as an **Identity Provider** in our detailed documentation at [Gravito Docs].

## Tools Required

* Visual Studio 2019
* Microsoft .Net Core SDK 3.1.* (Haven't tested this sample with upper versions, it might need some changes)

## Usage Guide

OIDC protocol is being used to connect with IdentityServer using code flow with PKCE as follows:

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
### Option Key Attributes:

* `ResponseType` is a mandatory request parameter which decides which flow to use. e.g. `token` or `code`.
* `Prompt` is used to show consent page / login page, if required.
It specifies whether the authorization server prompts the user for reauthentication and consent.
* `CallbackPath` after login where to redirect.
* `UsePkce` by default it is `false`, by setting it to `true` we are using PKCE with code flow.

`ServerAddress` and `ClientId` parameter values can be stored in `appsettings.json` or Azure Key-Vault.

* To secure API/Method using OpenID Connect, just put an `[Authorize]` attribute before the method/controller.
```c#
using Microsoft.AspNetCore.Authorization;

[Authorize]
public async Task<IActionResult> MethodName([parameters])
{
    return View();
}
```

## Handling Expired Token
* IdentityServer automatically sends the `refresh_token` to server and get the new `access_token` along with updated `refresh_token`.

## References
* [PKCE]
* [OpenID Documentation]
* [IdentityServer OIDC]
* appsettings.json file
```json
"Identity": {
    "ClientId": "client_id",
    "ServerAddress": "https://your-valid-identityserver-address/"
  }
```

## Visit Us At
[Website]

[//]: # (HyperLinks)

[Website]: https://www.gravito.net
[Gravito Docs]: https://docs.gravito.net/gravito-identity-provider/getting-started
[GitHub Repository]: https://github.com/GravitoLtd/gravito-ciam-client-dotnet
[OpenID Documentation]: https://openid.net/developers/specs/
[IdentityServer OIDC]: https://docs.identityserver.io/en/release/quickstarts/3_interactive_login.html
[PKCE]: https://oauth.net/2/pkce/

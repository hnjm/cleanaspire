// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.ComponentModel;
using System.ComponentModel.DataAnnotations;
using System.Diagnostics;
using System.Globalization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using CleanAspire.Domain.Identities;
using CleanAspire.Infrastructure.Persistence;
using Google.Apis.Auth;
using Microsoft.AspNetCore.Http.HttpResults;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
namespace CleanAspire.Api;

public static class IdentityApiAdditionalEndpointsExtensions
{
    // Validate the email address using DataAnnotations like the UserValidator does when RequireUniqueEmail = true.
    private static readonly EmailAddressAttribute _emailAddressAttribute = new();

    public static IEndpointRouteBuilder MapIdentityApiAdditionalEndpoints<TUser>(this IEndpointRouteBuilder endpoints)
            where TUser : class, new()
    {
        ArgumentNullException.ThrowIfNull(endpoints);
        var emailSender = endpoints.ServiceProvider.GetRequiredService<IEmailSender<TUser>>();
        var linkGenerator = endpoints.ServiceProvider.GetRequiredService<LinkGenerator>();
        var logger = endpoints.ServiceProvider.GetRequiredService<ILogger<IEndpointRouteBuilder>>();
        string? confirmEmailEndpointName = null;
        var routeGroup = endpoints.MapGroup("/account").WithTags("Authentication", "Account Management");
        routeGroup.MapPost("/logout", async (SignInManager<TUser> signInManager) =>
        {
            await signInManager.SignOutAsync().ConfigureAwait(false);
            logger.LogInformation("User has been logged out successfully.");
            return Results.Ok();
        })
        .RequireAuthorization()
        .WithSummary("Log out the current user.")
        .WithDescription("Logs out the currently authenticated user by signing them out of the system. This endpoint requires the user to be authorized before calling, and returns an HTTP 200 OK response upon successful logout.");

        routeGroup.MapGet("/profile", async Task<Results<Ok<ProfileResponse>, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }
            logger.LogInformation("User profile retrieved successfully.");
            return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
        })
        .RequireAuthorization()
        .WithSummary("Retrieve the user's profile")
        .WithDescription("Fetches the profile information of the authenticated user. " +
         "Returns 404 if the user is not found. Requires authorization.");


        routeGroup.MapPost("/profile", async Task<Results<Ok<ProfileResponse>, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, [FromBody] ProfileRequest request, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }

            if (!string.IsNullOrEmpty(request.Email) && !_emailAddressAttribute.IsValid(request.Email))
            {
                return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(request.Email)));
            }
            if (user is not ApplicationUser appUser)
                throw new InvalidCastException($"The provided user must be of type {nameof(ApplicationUser)}.");

            appUser.UserName = request.Username;
            appUser.Nickname = request.Nickname;
            appUser.TimeZoneId = request.TimeZoneId;
            appUser.LanguageCode = request.LanguageCode;
            appUser.SuperiorId = request.SuperiorId;
            appUser.TenantId = request.TenantId;
            appUser.AvatarUrl = request.AvatarUrl;
            await userManager.UpdateAsync(user).ConfigureAwait(false);
            if (!string.IsNullOrEmpty(request.Email))
            {
                var email = await userManager.GetEmailAsync(user);

                if (email != request.Email)
                {
                    await SendConfirmationEmailAsync(user, userManager, context, request.Email, isChange: true);
                }
            }

            return TypedResults.Ok(await CreateInfoResponseAsync(user, userManager));
        })
        .RequireAuthorization()
        .Produces<ProfileResponse>(StatusCodes.Status200OK)
        .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Update user profile information.")
        .WithDescription("Allows users to update their profile, including username, email, nickname, avatar, time zone, and language code.");

        routeGroup.MapPost("/updateEmail", async Task<Results<Ok, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, [FromBody] UpdateEmailRequest request, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }

            if (!string.IsNullOrEmpty(request.NewEmail) && !_emailAddressAttribute.IsValid(request.NewEmail))
            {
                return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidEmail(request.NewEmail)));
            }
            var email = await userManager.GetEmailAsync(user);
            if (email != request.NewEmail)
            {
                await SendConfirmationEmailAsync(user, userManager, context, request.NewEmail, isChange: true);
            }

            return TypedResults.Ok();
        })
        .RequireAuthorization()
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Update user email address.")
        .WithDescription("Allows users to update their email address and receive a confirmation email if it changes.");


        routeGroup.MapPost("/signup", async Task<Results<Created, ValidationProblem>>
                ([FromBody] SignupRequest request, HttpContext context) =>
            {
                var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
                var user = new TUser();
                if (!userManager.SupportsUserEmail)
                {
                    throw new NotSupportedException($"{nameof(MapIdentityApiAdditionalEndpoints)} requires a user store with email support.");
                }
                if (user is not ApplicationUser appUser)
                    throw new InvalidCastException($"The provided user must be of type {nameof(ApplicationUser)}.");
                appUser.Email = request.Email;
                appUser.UserName = request.Email;
                appUser.Nickname = request.Nickname;
                appUser.Provider = request.Provider;
                appUser.TenantId = request.TenantId;
                appUser.TimeZoneId = request.TimeZoneId;
                appUser.LanguageCode = request.LanguageCode;
                var result = await userManager.CreateAsync(user, request.Password);
                if (!result.Succeeded)
                {
                    return CreateValidationProblem(result);
                }
                logger.LogInformation("User signup successful.");
                await SendConfirmationEmailAsync(user, userManager, context, request.Email);
                return TypedResults.Created();
            })
            .AllowAnonymous()
            .WithSummary("User Signup")
            .WithDescription("Allows a new user to sign up by providing required details such as email, password, and tenant-specific information. This endpoint creates a new user account and sends a confirmation email for verification.");

        routeGroup.MapDelete("/deleteOwnerAccount", async Task<Results<Ok, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, SignInManager<TUser> signInManager, HttpContext context, [FromBody] DeleteUserRequest request) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }
            var userName = await userManager.GetUserNameAsync(user);
            if (string.IsNullOrEmpty(request.Username) || userName != request.Username)
            {
                return CreateValidationProblem(IdentityResult.Failed(userManager.ErrorDescriber.InvalidUserName(request.Username)));
            }
            var result = await userManager.DeleteAsync(user);
            if (!result.Succeeded)
            {
                return TypedResults.NotFound();
            }
            await signInManager.SignOutAsync();
            logger.LogInformation("User account deleted successfully.");
            return TypedResults.Ok();
        })
        .RequireAuthorization()
        .Produces(StatusCodes.Status204NoContent)
        .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Delete own user account.")
        .WithDescription("Allows users to delete their own account permanently.");

        routeGroup.MapGet("/confirmEmail", async Task<Results<ContentHttpResult, UnauthorizedHttpResult>>
            ([FromQuery] string userId, [FromQuery] string code, [FromQuery] string? changedEmail, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            if (await userManager.FindByIdAsync(userId) is not { } user)
            {
                return TypedResults.Unauthorized();
            }
            try
            {
                code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(code));
            }
            catch (FormatException)
            {
                return TypedResults.Unauthorized();
            }
            IdentityResult result;
            if (string.IsNullOrEmpty(changedEmail))
            {
                result = await userManager.ConfirmEmailAsync(user, code);
            }
            else
            {
                result = await userManager.ChangeEmailAsync(user, changedEmail, code);
                if (result.Succeeded)
                {
                    result = await userManager.SetUserNameAsync(user, changedEmail);
                }
            }
            if (!result.Succeeded)
            {
                return TypedResults.Unauthorized();
            }
            return TypedResults.Text("Thank you for confirming your email.");
        }).AllowAnonymous()
          .WithSummary("Confirm Email or Update Email Address")
          .WithDescription("Processes email confirmation or email change requests for a user. It validates the confirmation code, verifies the user ID, and updates the email if a new one is provided. Returns a success message upon successful confirmation or email update.")
          .Add(endpointBuilder =>
          {
              var finalPattern = ((RouteEndpointBuilder)endpointBuilder).RoutePattern.RawText;
              confirmEmailEndpointName = $"{nameof(MapIdentityApiAdditionalEndpoints)}-{finalPattern}";
              endpointBuilder.Metadata.Add(new EndpointNameMetadata(confirmEmailEndpointName));
          });



        routeGroup.MapGet("/google/loginUrl", ([FromQuery] string state, HttpContext context) =>
        {
            if (string.IsNullOrEmpty(state))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "state", new[] { "The state parameter is required." } }
                });
            }

            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientId = configuration["Authentication:Google:ClientId"];
            if (string.IsNullOrEmpty(clientId))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "clientId", new[] { "Google Client ID is not configured." } }
                });
            }

            var baseRedirectUri = configuration["ClientBaseUrl"];
            var redirectUri = string.IsNullOrEmpty(baseRedirectUri)
                ? $"{context.Request.Scheme}://{context.Request.Host}/external-login"
                : $"{baseRedirectUri}/external-login";

            if (!redirectUri.StartsWith(state))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "state", new[] { "The state parameter does not match the redirect URI." } }
                });
            }

            var googleAuthUrl =
                $"https://accounts.google.com/o/oauth2/v2/auth?" +
                $"response_type=code&" +
                $"client_id={Uri.EscapeDataString(clientId)}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                $"scope=openid%20profile%20email&" +
                $"state={Uri.EscapeDataString(state)}&" +
                $"nonce={Guid.NewGuid()}";

            return Results.Ok(googleAuthUrl);
        })
        .Produces<string>(StatusCodes.Status200OK)
        .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
        .WithSummary("Generate Google OAuth 2.0 Login URL")
        .WithDescription("Generates a Google OAuth 2.0 authorization URL for external login, dynamically determining the redirect URI and including the provided state parameter.");

        routeGroup.MapPost("/google/signIn", async (HttpContext context,
                [FromServices] IHttpClientFactory httpClientFactory,
                [FromQuery] string state,
                [FromQuery] string code) =>
        {
            if (string.IsNullOrEmpty(code))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "state", new[] { "The state parameter is required." } }
                });
            }
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientId = configuration["Authentication:Google:ClientId"];
            var clientSecret = configuration["Authentication:Google:ClientSecret"];
            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "clientId", new[] { "Google Client ID is not configured." } }
                });
            }
            var baseRedirectUri = configuration["ClientBaseUrl"];
            if (string.IsNullOrEmpty(baseRedirectUri))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "baseRedirectUri", new[] { "Client base URL is not configured." } }
                });
            }
            var redirectUri = $"{baseRedirectUri}/external-login";

            if (!redirectUri.StartsWith(state))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "state", new[] { "The state parameter does not match the redirect URI." } }
                });
            }

            var idTokenRequestContent = new FormUrlEncodedContent
            ([
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("grant_type", "authorization_code")
            ]);
            // Exchange the Google authorization code for access token
            var authorizationCodeExchangeRequest = await httpClientFactory.CreateClient().PostAsync(
                "https://oauth2.googleapis.com/token", idTokenRequestContent);

            if (!authorizationCodeExchangeRequest.IsSuccessStatusCode)
            {
                var responseMessage = await authorizationCodeExchangeRequest.Content.ReadAsStringAsync();
                return Results.BadRequest($"Authorization code exchange failed. {responseMessage}");
            }

            var idTokenContent = await authorizationCodeExchangeRequest.Content.ReadFromJsonAsync<GoogleTokenResponse>();
            if (idTokenContent?.id_token is null)
            {
                return Results.BadRequest("id_token not found in the response from the identity provider");
            }
            try
            {
                var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
                var dbcontext = context.RequestServices.GetRequiredService<ApplicationDbContext>();
                var signInManager = context.RequestServices.GetRequiredService<SignInManager<TUser>>();
                var validatedUser = await GoogleJsonWebSignature.ValidateAsync
                (
                    validationSettings: new() { Audience = [clientId] },
                    jwt: idTokenContent?.id_token
                );
                var email = validatedUser.Email;
                var user = await userManager.FindByEmailAsync(email);
                if (user is null)
                {
                    user = new TUser();
                    if (!userManager.SupportsUserEmail)
                    {
                        throw new NotSupportedException($"{nameof(MapIdentityApiAdditionalEndpoints)} requires a user store with email support.");
                    }
                    if (user is not ApplicationUser appUser)
                    {
                        throw new InvalidCastException($"The provided user must be of type {nameof(ApplicationUser)}.");
                    }

                    var tenantId = dbcontext.Tenants.FirstOrDefault()?.Id;
                    appUser.TenantId = tenantId;
                    appUser.Email = email;
                    appUser.UserName = email;
                    appUser.Nickname = validatedUser.Name;
                    appUser.Provider = "Google";
                    appUser.AvatarUrl = validatedUser.Picture;
                    appUser.LanguageCode = "en-US";
                    appUser.TimeZoneId = TimeZoneInfo.Local.Id;
                    appUser.EmailConfirmed = true;
                    appUser.RefreshToken = idTokenContent!.refresh_token;
                    appUser.RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(idTokenContent.expires_in);

                    var createResult = await userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        return Results.BadRequest("Failed to create a new user.");
                    }

                    // Associate external login with the new user
                    await userManager.AddLoginAsync(user, new UserLoginInfo("Google", validatedUser.Subject, "Google"));
                }

                signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
                var loginResult = await signInManager.ExternalLoginSignInAsync("Google", validatedUser.Subject, isPersistent: false);
                if (!loginResult.Succeeded)
                {
                    return Results.BadRequest("External login failed.");
                }

                return TypedResults.Ok();
            }
            catch (InvalidJwtException e)
            {
                return Results.BadRequest($"The id_token did not pass validation. {e.Message}");
            }
            catch (Exception e)
            {
                return Results.BadRequest($"The id_token did not pass validation. {e.Message}");
            }

        }).Produces(StatusCodes.Status200OK)
            .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
            .ProducesProblem(StatusCodes.Status400BadRequest)
           .WithSummary("External Login with Google OAuth")
            .WithDescription("Handles external login using Google OAuth 2.0. Exchanges an authorization code for tokens, validates the user's identity, and signs the user in.");

        routeGroup.MapGet("/microsoft/loginUrl", ([FromQuery] string state, HttpContext context) =>
        {
            if (string.IsNullOrEmpty(state))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            { "state", new[] { "The state parameter is required." } }
        });
            }
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientId = configuration["Authentication:Microsoft:ClientId"];
            if (string.IsNullOrEmpty(clientId))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
        {
            { "clientId", new[] { "Microsoft Client ID is not configured." } }
        });
            }
            var tenantId = configuration["Authentication:Microsoft:TenantId"] ?? "common";
            var baseRedirectUri = configuration["ClientBaseUrl"];
            var redirectUri = string.IsNullOrEmpty(baseRedirectUri)
                ? $"{context.Request.Scheme}://{context.Request.Host}/authentication-callback"
                : $"{baseRedirectUri}/authentication-callback";

            //    if (!redirectUri.StartsWith(state))
            //    {
            //        return Results.ValidationProblem(new Dictionary<string, string[]>
            //{
            //    { "state", new[] { "The state parameter does not match the redirect URI." } }
            //});
            //    }
            var scopes = "openid profile email User.Read offline_access";
            var microsoftAuthUrl =
                $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/authorize?" +
                $"response_type=code&" +
                $"client_id={Uri.EscapeDataString(clientId)}&" +
                $"redirect_uri={Uri.EscapeDataString(redirectUri)}&" +
                $"scope={Uri.EscapeDataString(scopes)}&" +
                $"state={Uri.EscapeDataString(state)}&" +
                $"response_mode=query";
            return Results.Ok(microsoftAuthUrl);
        })
      .Produces<string>(StatusCodes.Status200OK)
      .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
      .WithSummary("Generate Microsoft Azure OAuth 2.0 Login URL")
      .WithDescription("Generates a Microsoft Azure OAuth 2.0 authorization URL for external login, dynamically determining the redirect URI and including the provided state parameter.");


        routeGroup.MapPost("/microsoft/signIn", async (HttpContext context,
        [FromServices] IHttpClientFactory httpClientFactory,
        [FromQuery] string state,
        [FromQuery] string code) =>
        {
            if (string.IsNullOrEmpty(code))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "code", new[] { "The authorization code parameter is required." } }
                });
            }
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientId = configuration["Authentication:Microsoft:ClientId"];
            var clientSecret = configuration["Authentication:Microsoft:ClientSecret"];
            var tenantId = configuration["Authentication:Microsoft:TenantId"] ?? "common";

            if (string.IsNullOrEmpty(clientId) || string.IsNullOrEmpty(clientSecret))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
                {
                    { "clientId", new[] { "Microsoft Client ID or Client Secret is not configured." } }
                });
            }
            var baseRedirectUri = configuration["ClientBaseUrl"];
            if (string.IsNullOrEmpty(baseRedirectUri))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                { "baseRedirectUri", new[] { "Client base URL is not configured." } }
            });
            }
            var redirectUri = $"{baseRedirectUri}/authentication-callback";

            if (!redirectUri.StartsWith(state))
            {
                return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                { "state", new[] { "The state parameter does not match the redirect URI." } }
            });
            }

            // Exchange the authorization code for tokens
            var tokenRequestContent = new FormUrlEncodedContent
            ([
                new KeyValuePair<string, string>("code", code),
                new KeyValuePair<string, string>("client_id", clientId),
                new KeyValuePair<string, string>("client_secret", clientSecret),
                new KeyValuePair<string, string>("redirect_uri", redirectUri),
                new KeyValuePair<string, string>("grant_type", "authorization_code")
            ]);

            var tokenResponse = await httpClientFactory.CreateClient().PostAsync(
                $"https://login.microsoftonline.com/{tenantId}/oauth2/v2.0/token", tokenRequestContent);

            if (!tokenResponse.IsSuccessStatusCode)
            {
                var responseMessage = await tokenResponse.Content.ReadAsStringAsync();
                return Results.BadRequest($"Authorization code exchange failed. {responseMessage}");
            }

            var tokenContent = await tokenResponse.Content.ReadFromJsonAsync<MicrosoftTokenResponse>();
            if (tokenContent?.access_token is null)
            {
                return Results.BadRequest("access_token not found in the response from the identity provider");
            }

            try
            {
                var handler = new JwtSecurityTokenHandler();
                var principal = handler.ReadJwtToken(tokenContent.access_token);
                var email = principal.Claims.FirstOrDefault(c => c.Type == "email")?.Value;
                if (string.IsNullOrEmpty(email))
                {
                    return Results.BadRequest("Email not found in the token claims.");
                }
                var oid = principal.Claims.FirstOrDefault(c => c.Type == "oid")?.Value ?? tokenContent.id_token;
                var given_name = principal.Claims.FirstOrDefault(c => c.Type == "given_name")?.Value;
                var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
                var dbcontext = context.RequestServices.GetRequiredService<ApplicationDbContext>();
                var signInManager = context.RequestServices.GetRequiredService<SignInManager<TUser>>();

                var user = await userManager.FindByEmailAsync(email);
                
                // If user is still null, create using UserManager
                if (user == null)
                {
                    user = new TUser();
                    if (!userManager.SupportsUserEmail)
                    {
                        throw new NotSupportedException("Email support required.");
                    }

                    if (user is not ApplicationUser appUser)
                    {
                        throw new InvalidCastException("Expected user to be ApplicationUser.");
                    }

                    var microsofttenantId = dbcontext.Tenants.FirstOrDefault()?.Id;
                    appUser.TenantId = microsofttenantId;
                    appUser.Email = email;
                    appUser.UserName = email;
                    appUser.Nickname = given_name;
                    appUser.Provider = "Microsoft";
                    appUser.AvatarUrl = "";
                    appUser.LanguageCode = "en-US";
                    appUser.TimeZoneId = TimeZoneInfo.Local.Id;
                    appUser.EmailConfirmed = true;
                    appUser.RefreshToken = tokenContent.refresh_token;
                    appUser.RefreshTokenExpiryTime = DateTime.UtcNow.AddSeconds(tokenContent.expires_in);

                    var createResult = await userManager.CreateAsync(user);
                    if (!createResult.Succeeded)
                    {
                        return Results.BadRequest("Failed to create a new user.");
                    }
                    await userManager.AddLoginAsync(user, new UserLoginInfo("Microsoft", oid, "Microsoft"));
                }
                else
                {
                    var userId= await userManager.GetUserIdAsync(user);
                    await userManager.AddLoginAsync(user, new UserLoginInfo("Microsoft", oid, "Microsoft"));
                }

                signInManager.AuthenticationScheme = IdentityConstants.ApplicationScheme;
                var loginResult = await signInManager.ExternalLoginSignInAsync("Microsoft", oid, isPersistent: true);
                if (!loginResult.Succeeded)
                {
                    return Results.BadRequest("External login failed.");
                }

                return TypedResults.Ok();
            }
            catch (Exception e)
            {
                return Results.BadRequest($"Authentication failed. {e.Message}");
            }

        }).Produces(StatusCodes.Status200OK)
    .ProducesValidationProblem(StatusCodes.Status422UnprocessableEntity)
    .ProducesProblem(StatusCodes.Status400BadRequest)
    .WithSummary("External Login with Microsoft Azure OAuth")
    .WithDescription("Handles external login using Microsoft Azure OAuth 2.0. Exchanges an authorization code for tokens, validates the user's identity, and signs the user in.");

        routeGroup.MapGet("/generateAuthenticator", async Task<Results<Ok<AuthenticatorResponse>, ValidationProblem, NotFound>>
            (ClaimsPrincipal claimsPrincipal, HttpContext context, [FromQuery] string appName) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var urlEncoder = context.RequestServices.GetRequiredService<UrlEncoder>();
            if (await userManager.GetUserAsync(claimsPrincipal) is not { } user)
            {
                return TypedResults.NotFound();
            }
            if (string.IsNullOrEmpty(appName)) appName = "Blazor Aspire";
            var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            }
            var sharedKey = FormatKey(unformattedKey!);

            var email = await userManager.GetEmailAsync(user);
            var authenticatorUri = string.Format(
                    CultureInfo.InvariantCulture,
                    AuthenticatorUriFormat,
                    urlEncoder.Encode(appName),
                    urlEncoder.Encode(email!),
                    unformattedKey);
            return TypedResults.Ok(new AuthenticatorResponse(sharedKey, authenticatorUri));
        }).RequireAuthorization()
        .Produces<AuthenticatorResponse>(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status500InternalServerError)
        .WithSummary("Generate an Authenticator URI and shared key")
        .WithDescription("Generates a shared key and an Authenticator URI for a logged-in user. This endpoint is typically used to configure a TOTP authenticator app, such as Microsoft Authenticator or Google Authenticator.");


        routeGroup.MapPost("/enable2fa", async Task<Results<Ok, ValidationProblem, NotFound, BadRequest>>
         (ClaimsPrincipal claimsPrincipal, HttpContext context, [FromBody] Enable2faRequest request) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var urlEncoder = context.RequestServices.GetRequiredService<UrlEncoder>();
            var user = await userManager.GetUserAsync(claimsPrincipal);
            if (user is null)
            {
                return TypedResults.NotFound();
            }
            var unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            if (string.IsNullOrEmpty(unformattedKey))
            {
                await userManager.ResetAuthenticatorKeyAsync(user);
                unformattedKey = await userManager.GetAuthenticatorKeyAsync(user);
            }
            var sharedKey = FormatKey(unformattedKey!);
            var email = await userManager.GetEmailAsync(user);
            var authenticatorUri = string.Format(
                CultureInfo.InvariantCulture,
                AuthenticatorUriFormat,
                urlEncoder.Encode(request.AppName ?? "Blazor Aspire"),  // 使用用户提供的 appName 或默认值
                urlEncoder.Encode(email!),
                unformattedKey);

            var isValid = await userManager.VerifyTwoFactorTokenAsync(user, userManager.Options.Tokens.AuthenticatorTokenProvider, request.VerificationCode);
            if (isValid)
            {
                await userManager.SetTwoFactorEnabledAsync(user, true);
                logger.LogInformation("User has enabled 2fa.");
                return TypedResults.Ok();
            }
            else
            {
                return TypedResults.BadRequest();
            }
        }).RequireAuthorization()
          .Produces(StatusCodes.Status200OK)
          .ProducesProblem(StatusCodes.Status404NotFound)
          .ProducesProblem(StatusCodes.Status400BadRequest)
          .WithSummary("Enable Authenticator for the user")
          .WithDescription("This endpoint enables Two-Factor Authentication (TOTP) for a logged-in user. The user must first scan the provided QR code using an authenticator app, and then verify the generated code to complete the process.");

        routeGroup.MapGet("/disable2fa", async Task<Results<Ok, NotFound, BadRequest>>
        (ClaimsPrincipal claimsPrincipal, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Disable2FA");
            var user = await userManager.GetUserAsync(claimsPrincipal);
            if (user is null)
            {
                return TypedResults.NotFound();
            }
            var isTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);
            if (!isTwoFactorEnabled)
            {
                return TypedResults.BadRequest();
            }
            var result = await userManager.SetTwoFactorEnabledAsync(user, false);
            if (!result.Succeeded)
            {
                logger.LogError("Failed to disable 2FA");
                return TypedResults.BadRequest();
            }

            logger.LogInformation("User has disabled 2FA.");
            return TypedResults.Ok();
        })
        .RequireAuthorization()
        .Produces(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Disable Two-Factor Authentication for the user")
        .WithDescription("This endpoint disables Two-Factor Authentication (TOTP) for a logged-in user. The user must already have 2FA enabled for this operation to be valid.");

        routeGroup.MapPost("/login2fa", async Task<Results<Ok, ProblemHttpResult, NotFound>>
            ([FromBody] LoginRequest login, [FromQuery] bool? useCookies, [FromQuery] bool? useSessionCookies, HttpContext context) =>
        {
            var signInManager = context.RequestServices.GetRequiredService<SignInManager<TUser>>();
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var useCookieScheme = (useCookies == true) || (useSessionCookies == true);
            var isPersistent = (useCookies == true) && (useSessionCookies != true);
            signInManager.AuthenticationScheme = useCookieScheme ? IdentityConstants.ApplicationScheme : IdentityConstants.BearerScheme;

            var user = await userManager.FindByNameAsync(login.Email);
            if (user == null)
            {
                return TypedResults.NotFound();
            }

            var result = await signInManager.PasswordSignInAsync(login.Email, login.Password, isPersistent, lockoutOnFailure: true);

            if (result.RequiresTwoFactor)
            {
                if (!string.IsNullOrEmpty(login.TwoFactorCode))
                {
                    result = await signInManager.TwoFactorAuthenticatorSignInAsync(login.TwoFactorCode, isPersistent, rememberClient: isPersistent);
                }
                else if (!string.IsNullOrEmpty(login.TwoFactorRecoveryCode))
                {
                    result = await signInManager.TwoFactorRecoveryCodeSignInAsync(login.TwoFactorRecoveryCode);
                }
            }

            if (!result.Succeeded)
            {
                return TypedResults.Problem(result.ToString(), statusCode: StatusCodes.Status401Unauthorized);
            }

            // The signInManager already produced the needed response in the form of a cookie or bearer token.
            return TypedResults.Ok();
        }).AllowAnonymous()
        .Produces(StatusCodes.Status200OK)
        .ProducesProblem(StatusCodes.Status401Unauthorized)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Login with optional two-factor authentication")
        .WithDescription("This endpoint allows users to log in with their email and password. If two-factor authentication is enabled, the user must provide a valid two-factor code or recovery code. Supports persistent cookies or bearer tokens.");


        routeGroup.MapGet("generateRecoveryCodes", async Task<Results<Ok<RecoveryCodesResponse>, NotFound, BadRequest>>
        (ClaimsPrincipal claimsPrincipal, HttpContext context) =>
        {
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var logger = context.RequestServices.GetRequiredService<ILoggerFactory>().CreateLogger("Disable2FA");
            var user = await userManager.GetUserAsync(claimsPrincipal);
            if (user is null)
            {
                return TypedResults.NotFound();
            }
            var isTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);
            if (!isTwoFactorEnabled)
            {
                return TypedResults.BadRequest();
            }
            int codeCount = 8;
            var recoveryCodes = await userManager.GenerateNewTwoFactorRecoveryCodesAsync(user, codeCount);
            return TypedResults.Ok(new RecoveryCodesResponse(recoveryCodes));
        }).RequireAuthorization()
          .Produces<RecoveryCodesResponse>(StatusCodes.Status201Created)
        .ProducesProblem(StatusCodes.Status404NotFound)
        .ProducesProblem(StatusCodes.Status400BadRequest)
        .WithSummary("Generate recovery codes for two-factor authentication.")
        .WithDescription("Generates new recovery codes if two-factor authentication is enabled. "
                + "Returns 404 if the user is not found or 400 if 2FA is not enabled.");

        async Task SendConfirmationEmailAsync(TUser user, UserManager<TUser> userManager, HttpContext context, string email, bool isChange = false)
        {
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientBaseUrl = configuration["ClientBaseUrl"];
            if (string.IsNullOrEmpty(clientBaseUrl))
            {
                throw new InvalidOperationException("Client base URL is not configured.");
            }
            var code = isChange
                ? await userManager.GenerateChangeEmailTokenAsync(user, email)
                : await userManager.GenerateEmailConfirmationTokenAsync(user);
            code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));

            var userId = await userManager.GetUserIdAsync(user);

            // Construct the client-side URL
            var confirmEmailUrl = isChange
                ? $"{clientBaseUrl}/account/profile?userId={userId}&code={code}&changedEmail={email}"
                : $"{clientBaseUrl}/account/confirm-email?userId={userId}&code={code}";
            //var emailContent = isChange ? GenerateChangeEmailContent(confirmEmailUrl)
            //                            : GenerateSignupEmailContent(confirmEmailUrl);
            await emailSender.SendConfirmationLinkAsync(user, email, HtmlEncoder.Default.Encode(confirmEmailUrl));
        }
        routeGroup.MapPost("/forgotPassword", async Task<Results<Ok, ValidationProblem>>
            (HttpContext context, [FromBody] ForgotPasswordRequest resetRequest) =>
        {
            var configuration = context.RequestServices.GetRequiredService<IConfiguration>();
            var clientBaseUrl = configuration["ClientBaseUrl"];
            if (string.IsNullOrEmpty(clientBaseUrl))
            {
                throw new InvalidOperationException("Client base URL is not configured.");
            }
            var userManager = context.RequestServices.GetRequiredService<UserManager<TUser>>();
            var user = await userManager.FindByEmailAsync(resetRequest.Email);

            if (user is not null && await userManager.IsEmailConfirmedAsync(user))
            {
                var email = await userManager.GetEmailAsync(user);
                var code = await userManager.GeneratePasswordResetTokenAsync(user);
                code = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(code));
                var resetLink = $"{clientBaseUrl}/account/confirm-password-reset?email={email}&code={code}";
                await emailSender.SendPasswordResetLinkAsync(user, resetRequest.Email, HtmlEncoder.Default.Encode(resetLink));
            }

            // Don't reveal that the user does not exist or is not confirmed, so don't return a 200 if we would have
            // returned a 400 for an invalid code given a valid user email.
            return TypedResults.Ok();
        }).AllowAnonymous()
          .WithSummary("Request a password reset link")
          .WithDescription("Generates and sends a password reset link to the user's email if the email is registered and confirmed.");
        return endpoints;

       

    }
    private static async Task<ProfileResponse> CreateInfoResponseAsync<TUser>(TUser user, UserManager<TUser> userManager)
        where TUser : class
    {
        if (user is not ApplicationUser appUser)
            throw new InvalidCastException($"The provided user must be of type {nameof(ApplicationUser)}.");
        var isTwoFactorEnabled = await userManager.GetTwoFactorEnabledAsync(user);
        return new()
        {
            UserId = await userManager.GetUserIdAsync(user) ?? throw new NotSupportedException("Users must have an ID."),
            Username = await userManager.GetUserNameAsync(user) ?? throw new NotSupportedException("Users must have a username."),
            Email = await userManager.GetEmailAsync(user) ?? throw new NotSupportedException("Users must have an email."),
            IsEmailConfirmed = await userManager.IsEmailConfirmedAsync(user),
            TenantId = appUser.TenantId,
            Nickname = appUser.Nickname,
            LanguageCode = appUser.LanguageCode,
            Provider = appUser.Provider,
            SuperiorId = appUser.SuperiorId,
            TimeZoneId = appUser.TimeZoneId,
            AvatarUrl = appUser.AvatarUrl,
            IsTwoFactorEnabled = isTwoFactorEnabled
        };
    }


    private static ValidationProblem CreateValidationProblem(IdentityResult result)
    {
        // We expect a single error code and description in the normal case.
        // This could be golfed with GroupBy and ToDictionary, but perf! :P
        Debug.Assert(!result.Succeeded);
        var errorDictionary = new Dictionary<string, string[]>(1);

        foreach (var error in result.Errors)
        {
            string[] newDescriptions;

            if (errorDictionary.TryGetValue(error.Code, out var descriptions))
            {
                newDescriptions = new string[descriptions.Length + 1];
                Array.Copy(descriptions, newDescriptions, descriptions.Length);
                newDescriptions[descriptions.Length] = error.Description;
            }
            else
            {
                newDescriptions = [error.Description];
            }

            errorDictionary[error.Code] = newDescriptions;
        }

        return TypedResults.ValidationProblem(errorDictionary);
    }


    static string GenerateSignupEmailContent(string confirmEmailUrl)
    {
        return $@"
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                    }}
                    .email-container {{
                        max-width: 600px;
                        margin: auto;
                        padding: 20px;
                        border: 1px solid #ccc;
                        border-radius: 5px;
                        background: #f9f9f9;
                    }}
                    .email-header {{
                        text-align: center;
                        margin-bottom: 20px;
                    }}
                    .email-link {{
                        display: inline-block;
                        margin: 20px 0;
                        padding: 10px 20px;
                        background: #007bff;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                    }}
                    .email-link:hover {{
                        background: #0056b3;
                    }}
                </style>
            </head>
            <body>
                <div class='email-container'>
                    <p>Hello,</p>
                    <p>Thank you for signing up. Please confirm your email address by clicking the button below:</p>
                    <a href='{HtmlEncoder.Default.Encode(confirmEmailUrl)}' class='email-link'>Confirm Email</a>
                    <p>If the button above doesn't work, copy and paste the following URL into your browser:</p>
                    <p>{HtmlEncoder.Default.Encode(confirmEmailUrl)}</p>
                    <p>Thank you,<br>The Team</p>
                </div>
            </body>
        </html>";
    }

    static string GenerateChangeEmailContent(string confirmEmailUrl)
    {
        return $@"
        <html>
            <head>
                <style>
                    body {{
                        font-family: Arial, sans-serif;
                        line-height: 1.6;
                        color: #333;
                    }}
                    .email-container {{
                        max-width: 600px;
                        margin: auto;
                        padding: 20px;
                        border: 1px solid #ccc;
                        border-radius: 5px;
                        background: #f9f9f9;
                    }}
                    .email-header {{
                        text-align: center;
                        margin-bottom: 20px;
                    }}
                    .email-link {{
                        display: inline-block;
                        margin: 20px 0;
                        padding: 10px 20px;
                        background: #28a745;
                        color: white;
                        text-decoration: none;
                        border-radius: 5px;
                    }}
                    .email-link:hover {{
                        background: #218838;
                    }}
                </style>
            </head>
            <body>
                <div class='email-container'>
                    <p>Hello,</p>
                    <p>We received a request to update your email address. To confirm this change, please click the button below:</p>
                    <a href='{HtmlEncoder.Default.Encode(confirmEmailUrl)}' class='email-link'>Confirm New Email</a>
                    <p>If the button above doesn't work, copy and paste the following URL into your browser:</p>
                    <p>{HtmlEncoder.Default.Encode(confirmEmailUrl)}</p>
                    <p>If you did not request this change, please ignore this email or contact support for assistance.</p>
                    <p>Thank you,<br>The Team</p>
                </div>
            </body>
        </html>";
    }

    private static string FormatKey(string unformattedKey)
    {
        var result = new StringBuilder();
        int currentPosition = 0;
        while (currentPosition + 4 < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition, 4)).Append(' ');
            currentPosition += 4;
        }
        if (currentPosition < unformattedKey.Length)
        {
            result.Append(unformattedKey.AsSpan(currentPosition));
        }

        return result.ToString().ToLowerInvariant();
    }
    private const string AuthenticatorUriFormat = "otpauth://totp/{0}:{1}?secret={2}&issuer={0}&digits=6";

}

public class UpdateEmailRequest
{
    [Required]
    [Description("The new email address. Must be in a valid email format.")]
    [MaxLength(80, ErrorMessage = "Email cannot exceed 80 characters.")]
    [RegularExpression("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", ErrorMessage = "Invalid email format.")]
    public string NewEmail { get; set; } = string.Empty;
}

public class DeleteUserRequest
{
    [Description("Unique username for the user.")]
    [MaxLength(50, ErrorMessage = "Username cannot exceed 50 characters.")]
    [RegularExpression("^[a-zA-Z0-9_]*$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
    public required string Username { get; init; }
}

public sealed class ProfileRequest
{
    [Description("User's preferred nickname.")]
    [MaxLength(50, ErrorMessage = "Nickname cannot exceed 50 characters.")]
    [RegularExpression("^[a-zA-Z0-9_]*$", ErrorMessage = "Nickname can only contain letters, numbers, and underscores.")]
    public string? Nickname { get; init; }

    [Description("Unique username for the user.")]
    [MaxLength(50, ErrorMessage = "Username cannot exceed 50 characters.")]
    [RegularExpression("^[a-zA-Z0-9_]*$", ErrorMessage = "Username can only contain letters, numbers, and underscores.")]
    public required string Username { get; init; }
    [Required]
    [Description("User's email address. Must be in a valid email format.")]
    [MaxLength(80, ErrorMessage = "Email cannot exceed 80 characters.")]
    [RegularExpression("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", ErrorMessage = "Invalid email format.")]
    public required string Email { get; init; }
    [Description("User uploads an avatar image.")]
    public string? AvatarUrl { get; init; }
    [Description("User's time zone identifier, e.g., 'UTC', 'America/New_York'.")]
    [MaxLength(50, ErrorMessage = "TimeZoneId cannot exceed 50 characters.")]
    public string? TimeZoneId { get; set; }

    [Description("User's preferred language code, e.g., 'en-US'.")]
    [MaxLength(10, ErrorMessage = "LanguageCode cannot exceed 10 characters.")]
    [RegularExpression("^[a-z]{2,3}(-[A-Z]{2})?$", ErrorMessage = "Invalid language code format.")]
    public string? LanguageCode { get; set; }
    [Description("Tenant identifier for multi-tenant systems. Must be a GUID in version 7 format.")]
    [MaxLength(50, ErrorMessage = "Nickname cannot exceed 50 characters.")]
    public string? SuperiorId { get; init; }
    [Description("Tenant identifier for multi-tenant systems. Must be a GUID in version 7 format.")]
    [MaxLength(50, ErrorMessage = "Nickname cannot exceed 50 characters.")]
    public string? TenantId { get; set; }
}
public sealed class ProfileResponse
{
    public string? Nickname { get; init; }
    public string? Provider { get; init; }
    public string? TenantId { get; init; }
    public string? AvatarUrl { get; set; }
    public required string UserId { get; init; }
    public required string Username { get; init; }
    public required string Email { get; init; }
    public required bool IsEmailConfirmed { get; init; }
    public string? TimeZoneId { get; init; }
    public string? LanguageCode { get; init; }
    public string? SuperiorId { get; init; }
    public bool IsTwoFactorEnabled { get; init; }
}
public sealed class SignupRequest
{
    [Required]
    [Description("User's email address. Must be in a valid email format.")]
    [MaxLength(80, ErrorMessage = "Email cannot exceed 80 characters.")]
    [RegularExpression("^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}$", ErrorMessage = "Invalid email format.")]
    public required string Email { get; init; }

    [Required]
    [Description("User's password. Must meet the security criteria.")]
    [MinLength(8, ErrorMessage = "Password must be at least 8 characters long.")]
    [MaxLength(20, ErrorMessage = "Password cannot exceed 20 characters.")]
    [RegularExpression("^(?=.*[a-z])(?=.*[A-Z])(?=.*\\d)(?=.*[@$!%*?&])[A-Za-z\\d@$!%*?&]{8,50}$", ErrorMessage = "Password must be at least 8 characters long and include at least one uppercase letter, one lowercase letter, one number, and one special character.")]
    public required string Password { get; init; }

    [Description("User's preferred nickname.")]
    [MaxLength(50, ErrorMessage = "Nickname cannot exceed 50 characters.")]
    public string? Nickname { get; set; }

    [Description("Authentication provider, e.g., Local or Google.")]
    [MaxLength(20, ErrorMessage = "Provider cannot exceed 20 characters.")]
    public string? Provider { get; set; } = "Local";

    [Description("Tenant identifier for multi-tenant systems. Must be a GUID in version 7 format.")]
    [MaxLength(50, ErrorMessage = "Nickname cannot exceed 50 characters.")]
    public string? TenantId { get; set; }

    [Description("User's time zone identifier, e.g., 'UTC', 'America/New_York'.")]
    [MaxLength(50, ErrorMessage = "TimeZoneId cannot exceed 50 characters.")]
    public string? TimeZoneId { get; set; }

    [Description("User's preferred language code, e.g., 'en-US'.")]
    [MaxLength(10, ErrorMessage = "LanguageCode cannot exceed 10 characters.")]
    [RegularExpression("^[a-z]{2,3}(-[A-Z]{2})?$", ErrorMessage = "Invalid language code format.")]
    public string? LanguageCode { get; set; }
}


internal sealed record GoogleTokenResponse
{
    public string? access_token { get; set; }
    public int expires_in { get; set; }
    public string? id_token { get; set; }
    public string? scope { get; set; }
    public string? token_type { get; set; }
    public string? refresh_token { get; set; }
}
internal sealed record GoogleAuthResponse(
    string ExternalId,
    string Username,
    string Email,
    string? ProfilePicture
);



internal sealed record MicrosoftTokenResponse
{
    public string? access_token { get; set; }
    public string? token_type { get; set; }
    public string? refresh_token { get; set; }
    public int expires_in { get; set; }
    public string? id_token { get; set; }
    public string? scope { get; set; }
}


internal sealed record MicrosoftUserInfo
{
    public string? id { get; set; }
    public string? displayName { get; set; }
    public string? givenName { get; set; }
    public string? surname { get; set; }
    public string? mail { get; set; }
    public string? userPrincipalName { get; set; }
    public string? jobTitle { get; set; }
    public string? officeLocation { get; set; }
}

internal sealed record AuthenticatorResponse(
    string SharedKey,
    string AuthenticatorUri
);
internal sealed record Enable2faRequest(
    string? AppName,
    string VerificationCode
    );
internal sealed record RecoveryCodesResponse(
    IEnumerable<string> Codes
    );

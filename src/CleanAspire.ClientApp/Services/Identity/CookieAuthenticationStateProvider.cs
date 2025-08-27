// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System.Security.Claims;
using CleanAspire.Api.Client;
using CleanAspire.Api.Client.Models;
using CleanAspire.ClientApp.Services.JsInterop;
using Microsoft.AspNetCore.Components.Authorization;



using Microsoft.Kiota.Abstractions;


namespace CleanAspire.ClientApp.Services.Identity;

public class CookieAuthenticationStateProvider(ApiClient apiClient, UserProfileStore profileStore, IServiceProvider serviceProvider) : AuthenticationStateProvider, ISignInManagement
{
    private const string CACHEKEY_CREDENTIAL = "_Credential";
    private bool authenticated = false;
    private readonly ClaimsPrincipal unauthenticated = new(new ClaimsIdentity());
    public override async Task<AuthenticationState> GetAuthenticationStateAsync()
    {
        var indexedDb = serviceProvider.GetRequiredService<IndexedDbCache>();
        var onlineStatusInterop = serviceProvider.GetRequiredService<OnlineStatusInterop>();
        var offlineState = serviceProvider.GetRequiredService<OfflineModeState>();
        authenticated = false;
        // default to not authenticated
        var user = unauthenticated;
        ProfileResponse? profileResponse = null;
        try
        {
            bool enableOffline = offlineState.Enabled;
            var isOnline = await onlineStatusInterop.GetOnlineStatusAsync();
            if (isOnline)
            {
                // the user info endpoint is secured, so if the user isn't logged in this will fail
                profileResponse = await apiClient.Account.Profile.GetAsync();
                // store the profile to indexedDB
                if (profileResponse != null && enableOffline)
                {
                    await indexedDb.SaveDataAsync(IndexedDbCache.DATABASENAME, CACHEKEY_CREDENTIAL, profileResponse);
                }
            }
            else if (enableOffline)
            {
                profileResponse = await indexedDb.GetDataAsync<ProfileResponse>(IndexedDbCache.DATABASENAME, CACHEKEY_CREDENTIAL);
            }

            profileStore.Set(profileResponse);
            if (profileResponse != null)
            {
                // in this example app, name and email are the same
                var claims = new List<Claim>
                    {
                        new(ClaimTypes.NameIdentifier,profileResponse.UserId),
                        new(ClaimTypes.Name,profileResponse.Username),
                        new(ClaimTypes.Email, profileResponse.Email),
                        new(ClaimTypes.GivenName, profileResponse.Nickname),
                        new(ClaimTypes.Locality, profileResponse.TimeZoneId),
                        new(ClaimTypes.Country, profileResponse.LanguageCode),
                    };

                // set the principal
                var id = new ClaimsIdentity(claims, nameof(CookieAuthenticationStateProvider));
                user = new ClaimsPrincipal(id);
                authenticated = true;
            }
        }
        catch { }
        // return the state
        return new AuthenticationState(user);
    }

    public async Task LoginAsync(LoginRequest request, bool remember = true, CancellationToken cancellationToken = default)
    {
        var indexedDb = serviceProvider.GetRequiredService<IndexedDbCache>();
        var onlineStatusInterop = serviceProvider.GetRequiredService<OnlineStatusInterop>();
        var offlineState = serviceProvider.GetRequiredService<OfflineModeState>();
        try
        {
            bool offlineModel = offlineState.Enabled;
            var isOnline = await onlineStatusInterop.GetOnlineStatusAsync();
            if (isOnline)
            {
                // Online login
                var response = await apiClient.Account.Login2fa.PostAsync(request, options =>
                {
                    options.QueryParameters.UseCookies = remember;
                    options.QueryParameters.UseSessionCookies = !remember;
                }, cancellationToken);
                if (offlineModel)
                {
                    // Store response in IndexedDB for offline access
                    await indexedDb.SaveDataAsync(IndexedDbCache.DATABASENAME,request.Email!, request.Email);
                }
            }
            else if (offlineModel)
            {
                // Offline login logic
                var storedToken = await indexedDb.GetDataAsync<string>(IndexedDbCache.DATABASENAME, request.Email!);
                if (storedToken == null)
                {
                    throw new InvalidOperationException("No offline data available for the provided email.");
                }
            }
            // Refresh authentication state
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        catch (ProblemDetails)
        {
            throw;
        }
        catch (ApiException)
        {
            // Log and re-throw API exception
            throw;
        }
        catch (Exception)
        {
            // Log and re-throw general exception
            throw;
        }
    }


    public async Task LogoutAsync(CancellationToken cancellationToken = default)
    {
        await apiClient.Account.Logout.PostAsync(cancellationToken: cancellationToken);
        // need to refresh auth state
        NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
    }

    public async Task LoginWithGoogle(string authorizationCode, string state, CancellationToken cancellationToken = default)
    {
        try
        {
            await apiClient.Account.Google.SignIn.PostAsync(q=>
            {
                q.QueryParameters.Code = authorizationCode;
                q.QueryParameters.State = state;
            }, cancellationToken);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());
        }
        catch(ProblemDetails)
        {
            // Log and re-throw problem details exception
            throw;
        }
        catch(ApiException)
        {
            // Log and re-throw API exception
            throw;
        }
        catch(Exception)
        {
            // Log and re-throw general exception
            throw;
        }
    }

    public async Task LoginWithMicrosoft(string authorizationCode, string state, CancellationToken cancellationToken = default)
    {
        try
        {
            await apiClient.Account.Microsoft.SignIn.PostAsync(q =>
            {
                q.QueryParameters.Code = authorizationCode;
                q.QueryParameters.State = state;
            }, cancellationToken);
            NotifyAuthenticationStateChanged(GetAuthenticationStateAsync());

        }
        catch (ProblemDetails)
        {

            throw;
        }
        catch (ApiException)
        {

            throw;
        }
        catch (Exception)
        {

            throw;
        }
    }
}


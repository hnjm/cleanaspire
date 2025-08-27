// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using CleanAspire.Api.Client.Models;

namespace CleanAspire.ClientApp.Services.Identity;

public interface ISignInManagement
{
    Task LoginAsync(LoginRequest request, bool remember = true, CancellationToken cancellationToken = default);
    Task LoginWithGoogle(string authorizationCode, string state, CancellationToken cancellationToken = default);
    Task LoginWithMicrosoft(string authorizationCode, string state, CancellationToken cancellationToken = default);
    Task LogoutAsync(CancellationToken cancellationToken = default);
}


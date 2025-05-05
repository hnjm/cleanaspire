// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.
// See the LICENSE file in the project root for more information.

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using CleanAspire.Application.Common.Interfaces;
using CleanAspire.Infrastructure.Persistence.Seed;
using CleanAspire.Infrastructure.Persistence;
using Microsoft.EntityFrameworkCore.Diagnostics;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using CleanAspire.Infrastructure.Persistence.Interceptors;
using CleanAspire.Infrastructure.Configurations;
using Microsoft.Extensions.Options;
using CleanAspire.Infrastructure.Services;
using Microsoft.Extensions.Hosting;
using CleanAspire.Application.Common.Services;
using ZiggyCreatures.Caching.Fusion;


namespace CleanAspire.Infrastructure;

public static class DependencyInjection
{
    private const string DATABASE_SETTINGS_KEY = "DatabaseSettings";
    private const string NPGSQL_ENABLE_LEGACY_TIMESTAMP_BEHAVIOR = "Npgsql.EnableLegacyTimestampBehavior";
    private const string MSSQL_MIGRATIONS_ASSEMBLY = "CleanAspire.Migrators.MSSQL";
    private const string SQLITE_MIGRATIONS_ASSEMBLY = "CleanAspire.Migrators.SQLite";
    private const string POSTGRESQL_MIGRATIONS_ASSEMBLY = "CleanAspire.Migrators.PostgreSQL";
    private const string USE_IN_MEMORY_DATABASE_KEY = "UseInMemoryDatabase";
    private const string IN_MEMORY_DATABASE_NAME = "CleanAspireDb";

    public static IServiceCollection AddInfrastructure(this IServiceCollection services,
        IConfiguration configuration)
    {
        services.Configure<MinioOptions>(configuration.GetSection(MinioOptions.Key))
            .AddSingleton(s => s.GetRequiredService<IOptions<MinioOptions>>().Value);
        services
            .AddDatabase(configuration)
            .AddFusionCacheService()
            .AddScoped<IUploadService, MinioUploadService>();
 

        return services;
    }

    private static IServiceCollection AddDatabase(this IServiceCollection services,
   IConfiguration configuration)
    {
        services.Configure<DatabaseSettings>(configuration.GetSection(DATABASE_SETTINGS_KEY))
            .AddSingleton(s => s.GetRequiredService<IOptions<DatabaseSettings>>().Value);
        services.AddScoped<IDateTime, UtcDateTime>()
             .AddScoped<ICurrentUserContext, CurrentUserContext>();
        services.AddScoped<ICurrentUserAccessor, CurrentUserAccessor>()
             .AddScoped<ICurrentUserContextSetter, CurrentUserContextSetter>()
            .AddScoped<ICurrentUserAccessor, CurrentUserAccessor>()
            .AddScoped<ISaveChangesInterceptor, AuditableEntityInterceptor>()
            .AddScoped<ISaveChangesInterceptor, DispatchDomainEventsInterceptor>();


        if (configuration.GetValue<bool>(USE_IN_MEMORY_DATABASE_KEY))
        {
            services.AddDbContext<ApplicationDbContext>((p, options) =>
            {
                options.UseInMemoryDatabase(IN_MEMORY_DATABASE_NAME);
                options.AddInterceptors(p.GetServices<ISaveChangesInterceptor>());
                options.EnableSensitiveDataLogging();
            });

        }
        else
        {
            services.AddDbContext<ApplicationDbContext>((p, m) =>
            {
                var databaseSettings = p.GetRequiredService<IOptions<DatabaseSettings>>().Value;
                m.AddInterceptors(p.GetServices<ISaveChangesInterceptor>());
                m.UseExceptionProcessor(databaseSettings.DBProvider);
                m.UseDatabase(databaseSettings.DBProvider, databaseSettings.ConnectionString);
            });

        }


        services.AddScoped<IDbContextFactory<ApplicationDbContext>, BlazorContextFactory<ApplicationDbContext>>();
        services.AddScoped<IApplicationDbContext>(provider =>
            provider.GetRequiredService<IDbContextFactory<ApplicationDbContext>>().CreateDbContext());
        services.AddScoped<ApplicationDbContextInitializer>();

        return services;
    }


    private static DbContextOptionsBuilder UseDatabase(this DbContextOptionsBuilder builder, string dbProvider,
            string connectionString)
    {
        switch (dbProvider.ToLowerInvariant())
        {
            case DbProviderKeys.Npgsql:
                AppContext.SetSwitch(NPGSQL_ENABLE_LEGACY_TIMESTAMP_BEHAVIOR, true);
                builder.UseNpgsql(connectionString,
                        e => e.MigrationsAssembly(POSTGRESQL_MIGRATIONS_ASSEMBLY))
                    .UseSnakeCaseNamingConvention();
                break;
            case DbProviderKeys.SqlServer:
                builder.UseSqlServer(connectionString,
                    e => e.MigrationsAssembly(MSSQL_MIGRATIONS_ASSEMBLY));
                break;
            case DbProviderKeys.SqLite:
                builder.UseSqlite(connectionString,
                    e => e.MigrationsAssembly(SQLITE_MIGRATIONS_ASSEMBLY));
                break;
            default:
                throw new InvalidOperationException($"DB Provider {dbProvider} is not supported.");
        }
        // Ignore the “PendingModelChangesWarning” so that add-migration can succeed
        builder.ConfigureWarnings(w =>
        w.Ignore(RelationalEventId.PendingModelChangesWarning));
        return builder;
    }
    private static DbContextOptionsBuilder UseExceptionProcessor(this DbContextOptionsBuilder builder, string dbProvider)
    {

        switch (dbProvider.ToLowerInvariant())
        {
            case DbProviderKeys.Npgsql:
                EntityFramework.Exceptions.PostgreSQL.ExceptionProcessorExtensions.UseExceptionProcessor(builder);
                return builder;

            case DbProviderKeys.SqlServer:
                EntityFramework.Exceptions.SqlServer.ExceptionProcessorExtensions.UseExceptionProcessor(builder);
                return builder;


            case DbProviderKeys.SqLite:
                EntityFramework.Exceptions.Sqlite.ExceptionProcessorExtensions.UseExceptionProcessor(builder);
                return builder;

            default:
                throw new InvalidOperationException($"DB Provider {dbProvider} is not supported.");
        }
    }


    private static IServiceCollection AddFusionCacheService(this IServiceCollection services)
    {
        services.AddMemoryCache();
        services.AddFusionCache().WithDefaultEntryOptions(new FusionCacheEntryOptions
        {
            // CACHE DURATION
            Duration = TimeSpan.FromMinutes(120),
            // FAIL-SAFE OPTIONS
            IsFailSafeEnabled = true,
            FailSafeMaxDuration = TimeSpan.FromHours(8),
            FailSafeThrottleDuration = TimeSpan.FromSeconds(30),
            // FACTORY TIMEOUTS
            FactorySoftTimeout = TimeSpan.FromSeconds(10),
            FactoryHardTimeout = TimeSpan.FromSeconds(30),
            AllowTimedOutFactoryBackgroundCompletion = true,
        });
        return services;
    }
    public static async Task InitializeDatabaseAsync(this IHost host)
    {
        using (var scope = host.Services.CreateScope())
        {
            var initializer = scope.ServiceProvider.GetRequiredService<ApplicationDbContextInitializer>();
            await initializer.InitialiseAsync().ConfigureAwait(false);

            var env = host.Services.GetRequiredService<IHostEnvironment>();
            if (env.IsDevelopment())
            {
                await initializer.SeedAsync().ConfigureAwait(false);
            }
        }
    }
}


internal class DbProviderKeys
{
    public const string Npgsql = "postgresql";
    public const string SqlServer = "mssql";
    public const string SqLite = "sqlite";
}

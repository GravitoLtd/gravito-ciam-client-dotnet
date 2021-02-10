using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System;
using System.Threading.Tasks;

namespace Gravito.CIAM
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        public void ConfigureServices(IServiceCollection services)
        {
            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = "cookie";
                options.DefaultSignInScheme = "cookie";
                options.DefaultChallengeScheme = "oidc";
            })
            .AddCookie("cookie", options =>
            {
                options.ExpireTimeSpan = new TimeSpan(0, 1, 0);
            })
            .AddOpenIdConnect("oidc", options =>
            {
                options.Authority = Configuration.GetSection("Identity:ServerAddress").Value;
                options.ClientId = "custom_token_client11";
                options.SaveTokens = true;
                options.ResponseType = "code";
                options.SignedOutCallbackPath = "/Home/Index";
                options.RequireHttpsMetadata = false; // dev only
                options.Prompt = "consent";
                options.ResponseMode = "form_post";
                options.CallbackPath = "/signin-oidc";
                options.UsePkce = true;

                // configure cookie claim mapping
                options.ClaimActions.DeleteClaim("amr");

                options.GetClaimsFromUserInfoEndpoint = true;

                // configure scope
                options.Scope.Clear();
                options.Scope.Add("profile");
                options.Scope.Add("API");
                options.Scope.Add("openid");
                options.Scope.Add("offline_access");

                options.Events.OnAuthorizationCodeReceived = context =>
                {
                    // only when authorization code is being swapped for tokens
                    if (context.TokenEndpointRequest?.GrantType == OpenIdConnectGrantTypes.AuthorizationCode)
                    {
                        // get stored code_verifier
                        if (context.Properties.Items.TryGetValue("code_verifier", out var codeVerifier))
                        {
                            // add code_verifier to token request
                            context.TokenEndpointRequest.Parameters.Add("code_verifier", codeVerifier);
                        }
                    }

                    return Task.CompletedTask;
                };
            });

            services.AddHttpClient();
            services.AddControllersWithViews();
        }

        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }
            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapControllerRoute(
                    name: "default",
                    pattern: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

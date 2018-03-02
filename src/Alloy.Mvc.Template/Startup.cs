using System;
using System.Configuration;
using System.Globalization;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using System.Web;

using Owin;
using Microsoft.Owin;
using Microsoft.Owin.Extensions;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Cookies;
using Microsoft.Owin.Security.Notifications;
using Microsoft.Owin.Security.OpenIdConnect;

using EPiServer.Security;
using EPiServer.ServiceLocation;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;


[assembly: OwinStartup(typeof(AlloyTemplates.Startup))]

namespace AlloyTemplates
{
    public class Startup
    {
        // <add key="ida:AADInstance" value="https://login.microsoftonline.com/{0}" />
        private static readonly string aadInstance = ConfigurationManager.AppSettings["ida:AADInstance"];

        // <add key="ida:ClientId" value="Client ID from Azure AD application" />
        private static string clientId = ConfigurationManager.AppSettings["ida:ClientId"];

        //<add key="ida:PostLogoutRedirectUri" value="https://the logout post uri/" />
        private static readonly string postLogoutRedirectUri = ConfigurationManager.AppSettings["ida:PostLogoutRedirectUri"];

        private static string commonAuthority = String.Format(CultureInfo.InvariantCulture, aadInstance, "common/");

        const string LogoutPath = "/logout";



        public void Configuration(IAppBuilder app)
        {
            app.SetDefaultSignInAsAuthenticationType(CookieAuthenticationDefaults.AuthenticationType);
            app.UseCookieAuthentication(new CookieAuthenticationOptions());
            app.UseOpenIdConnectAuthentication(new OpenIdConnectAuthenticationOptions
            {
                ClientId = clientId,
                Authority = commonAuthority,
                PostLogoutRedirectUri = postLogoutRedirectUri,
                TokenValidationParameters = new Microsoft.IdentityModel.Tokens.TokenValidationParameters
                {
                    ValidateIssuer = false,
                    RoleClaimType = ClaimTypes.Role
                },
                Notifications = new OpenIdConnectAuthenticationNotifications
                {
                    AuthenticationFailed = context =>
                    {
                        context.HandleResponse();
                        context.Response.Write(context.Exception.Message);
                        return Task.FromResult(0);
                    },
                  
                    RedirectToIdentityProvider = context =>
                    {
                        // Here you can change the return uri based on multisite
                        HandleMultiSitereturnUrl(context);

                        // To avoid a redirect loop to the federation server send 403 
                        // when user is authenticated but does not have access
                        if (context.OwinContext.Response.StatusCode == 401 &&
                            context.OwinContext.Authentication.User.Identity.IsAuthenticated)
                        {
                            context.OwinContext.Response.StatusCode = 403;
                            context.HandleResponse();
                        }
                        return Task.FromResult(0);
                    },
                    SecurityTokenValidated = (ctx) =>
                    {
                        var redirectUri = new Uri(ctx.AuthenticationTicket.Properties.RedirectUri, UriKind.RelativeOrAbsolute);
                        if (redirectUri.IsAbsoluteUri)
                        {
                            ctx.AuthenticationTicket.Properties.RedirectUri = redirectUri.PathAndQuery;
                        }
                        //Sync user and the roles to EPiServer in the background
                       ServiceLocator.Current.GetInstance<ISynchronizingUserService>().
                        SynchronizeAsync((ClaimsIdentity)ctx.AuthenticationTicket.Identity).ConfigureAwait(false).GetAwaiter().GetResult();
                        return Task.FromResult(0);
                    }
                }
            });
            app.UseStageMarker(PipelineStage.Authenticate);
            app.Map(LogoutPath, map =>
            {
                map.Run(ctx =>
                {
                    ctx.Authentication.SignOut();
                    return Task.FromResult(0);
                });
            });
        }


        private void HandleMultiSitereturnUrl(
                RedirectToIdentityProviderNotification<OpenIdConnectMessage, OpenIdConnectAuthenticationOptions> context)
        {
            // here you change the context.ProtocolMessage.RedirectUri to corresponding siteurl
            // this is a sample of how to change redirecturi in the multi-tenant environment
            if (context.ProtocolMessage.RedirectUri == null)
            {
                var currentUrl = EPiServer.Web.SiteDefinition.Current.SiteUrl;
                context.ProtocolMessage.RedirectUri = new UriBuilder(
                   currentUrl.Scheme,
                   currentUrl.Host,
                   currentUrl.Port,
                   HttpContext.Current.Request.Url.AbsolutePath).ToString();
            }
        }
    }
}

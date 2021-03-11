using Gravito.CIAM.Models;
using IdentityModel.Client;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Threading.Tasks;

namespace Gravito.CIAM.Controllers
{
    public class HomeController : Controller
    {
        private readonly IHttpClientFactory _httpClientFactory;
        public IConfiguration Configuration { get; }
        
        public HomeController(IHttpClientFactory httpClientFactory, IConfiguration configuration)
        {
            Configuration = configuration;
            _httpClientFactory = httpClientFactory;
        }

        public IActionResult Index()
        {
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Secret()
        {
            var accessToken = await HttpContext.GetTokenAsync("access_token");
            var idToken = await HttpContext.GetTokenAsync("id_token");
            var refreshToken = await HttpContext.GetTokenAsync("refresh_token");

            // get the claims in id_token & access_token
            var _accessToken = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);
            var _idToken = new JwtSecurityTokenHandler().ReadJwtToken(idToken);

            // pass the information to view and show on page
            var tr = new TokenResponseModel()
            {
                AccessToken = accessToken,
                ReadAccessToken = _accessToken,
                IdToken = idToken,
                ReadIdToken = _idToken,
                RefreshToken = refreshToken,
            };


            ViewData["Title"] = "Secret content here";

            return View(tr);
        }

        [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
        public IActionResult Error()
        {
            return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
        }

        #region -- Manually refreshes the access_token, we are not using it as IS4 automatically does that for us --
        //private async Task RefreshAccessToken()
        //{
        //    var serverClient = _httpClientFactory.CreateClient();
        //    var discoveryDocument = await serverClient.GetDiscoveryDocumentAsync(Configuration.GetSection("Identity:ServerAddress").Value);

        //    var accessToken = await HttpContext.GetTokenAsync("access_token");
        //    var idToken = await HttpContext.GetTokenAsync("id_token");
        //    var refreshToken = await HttpContext.GetTokenAsync("refresh_token");
        //    var refreshTokenClient = _httpClientFactory.CreateClient();

        //    var tokenResponse = await refreshTokenClient.RequestRefreshTokenAsync(
        //        new RefreshTokenRequest
        //        {
        //            Address = discoveryDocument.TokenEndpoint,
        //            RefreshToken = refreshToken,
        //            ClientId = "custom_token_client11",
        //            //ClientSecret = "client_secret_mvc"
        //        });

        //    var authInfo = await HttpContext.AuthenticateAsync("cookie");

        //    authInfo.Properties.UpdateTokenValue("access_token", tokenResponse.AccessToken);
        //    authInfo.Properties.UpdateTokenValue("id_token", tokenResponse.IdentityToken);
        //    authInfo.Properties.UpdateTokenValue("refresh_token", tokenResponse.RefreshToken);

        //    await HttpContext.SignInAsync("cookie", authInfo.Principal, authInfo.Properties);
        //}

        #endregion
    }
}

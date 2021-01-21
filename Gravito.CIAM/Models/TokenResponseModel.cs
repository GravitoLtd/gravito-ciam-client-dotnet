using System.IdentityModel.Tokens.Jwt;

namespace Gravito.CIAM.Models
{
    public class TokenResponseModel
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string IdToken { get; set; }
        public JwtSecurityToken ReadAccessToken { get; set; }
        public JwtSecurityToken ReadIdToken { get; set; }
    }
}

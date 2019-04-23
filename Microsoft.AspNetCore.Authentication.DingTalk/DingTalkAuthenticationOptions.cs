using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public class DingTalkAuthenticationOptions : OAuthOptions
    {
        public DingTalkAuthenticationOptions()
        {
            ClaimsIssuer = DingTalkAuthenticationDefaults.Issuer;
            CallbackPath = new PathString(DingTalkAuthenticationDefaults.CallbackPath);

            AuthorizationEndpoint = DingTalkAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = DingTalkAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = DingTalkAuthenticationDefaults.UserInformationEndpoint;
        }
    }
}

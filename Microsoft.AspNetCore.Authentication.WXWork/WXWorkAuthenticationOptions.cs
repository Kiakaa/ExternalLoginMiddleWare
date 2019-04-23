using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.Http;
using System.Linq;
using System.Security.Claims;

namespace Microsoft.AspNetCore.Authentication.WXWork
{
    /// <summary>
    /// 企业微信OAuth配置项
    /// </summary>
    public class WXWorkAuthenticationOptions : OAuthOptions
    {
        public WXWorkAuthenticationOptions()
        {
            ClaimsIssuer = WXWorkAuthenticationDefaults.Issuer;
            CallbackPath = new PathString(WXWorkAuthenticationDefaults.CallbackPath);
            
            AuthorizationEndpoint = WXWorkAuthenticationDefaults.AuthorizationEndpoint;
            TokenEndpoint = WXWorkAuthenticationDefaults.TokenEndpoint;
            UserInformationEndpoint = WXWorkAuthenticationDefaults.UserInformationEndpoint;
        }
    }
}

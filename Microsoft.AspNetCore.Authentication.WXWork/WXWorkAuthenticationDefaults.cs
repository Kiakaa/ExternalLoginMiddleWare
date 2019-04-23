namespace Microsoft.AspNetCore.Authentication.WXWork
{
   /// <summary>
   /// 企业微信第三方单点登录默认OAuth配置项
   /// </summary>
    public static class WXWorkAuthenticationDefaults
    {
        public const string AuthenticationScheme = "WXWork";

        public static readonly string DisplayName = "企业微信";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-wxwork";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "WXWork";

        /// <summary>
        /// 第一步，获取授权（auth_code）地址，Default value for <see cref="OAuth.OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public static readonly string AuthorizationEndpoint = "https://open.work.weixin.qq.com/wwopen/sso/3rd_qrConnect";

        /// <summary>
        /// 第二步，通过corpid,provider_secret换取provider_token地址
        /// </summary>
        public static readonly string TokenEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/service/get_provider_token";

        /// <summary>
        /// 第三步，用第一步用户授权后取到的auth_code和第二步渠道的ProviderToken，取得用户个人信息
        /// </summary>
        public static readonly string UserInformationEndpoint = "https://qyapi.weixin.qq.com/cgi-bin/service/get_login_info";
    }
}

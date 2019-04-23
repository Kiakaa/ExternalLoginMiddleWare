namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public static class DingTalkAuthenticationDefaults
    {
        public const string AuthenticationScheme = "DingTalk";

        public static readonly string DisplayName = "阿里钉钉";

        /// <summary>
        /// Default value for <see cref="RemoteAuthenticationOptions.CallbackPath"/>.
        /// </summary>
        public const string CallbackPath = "/signin-dingtalk";

        /// <summary>
        /// Default value for <see cref="AuthenticationSchemeOptions.ClaimsIssuer"/>.
        /// </summary>
        public const string Issuer = "DingTalk";

        /// <summary>
        /// 第一步，获取授权码（tmp_auth_code）地址，Default value for <see cref="OAuth.OAuthOptions.AuthorizationEndpoint"/>.
        /// </summary>
        public static readonly string AuthorizationEndpoint = "https://oapi.dingtalk.com/connect/qrconnect";

        /// <summary>
        /// 第二步，通过appid,appsecret换取access_token地址
        /// </summary>
        public static readonly string TokenEndpoint = "https://oapi.dingtalk.com/sns/gettoken";

        /// <summary>
        /// 第三步，使用第一步获取的临时授权码code(tmp_auth_code：用户授权给钉钉开放应用的免登授权码)，和第二步的access_token appid,appsecret换取持久授权码
        /// </summary>
        public static readonly string PersistentTokenEndpoint = "https://oapi.dingtalk.com/sns/get_persistent_code";

        /// <summary>
        /// 第四步，使用第三步获取的持久授权码，换取用户授权的token：SNS_TOKEN
        /// </summary>
        public static readonly string SNSTokenEndpoint = "https://oapi.dingtalk.com/sns/get_sns_token";

        /// <summary>
        /// 第五步，使用第四步获取的SNS_TOKEN，获取该用户的个人信息
        /// </summary>
        public static readonly string UserInformationEndpoint = "https://oapi.dingtalk.com/sns/getuserinfo";
    }
}

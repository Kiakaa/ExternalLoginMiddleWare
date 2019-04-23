using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Authentication.WXWork
{
    /// <summary>
    /// 企业微信认证中间件
    /// 提供不同的方法签名，在注册中间件时使用。
    /// </summary>
    public static class WXWorkAuthenticationExtensions
    {
        // 注册中间件时使用，只传入AuthenticationScheme
        public static AuthenticationBuilder AddWXWorkAuthentication(this AuthenticationBuilder builder)
            => builder.AddWXWorkAuthentication(WXWorkAuthenticationDefaults.AuthenticationScheme, _ => { });

        //注册中间件时使用，传入WXWorkOptions
        public static AuthenticationBuilder AddWXWorkAuthentication(this AuthenticationBuilder builder, Action<WXWorkAuthenticationOptions> configureOptions)
            => builder.AddWXWorkAuthentication(WXWorkAuthenticationDefaults.AuthenticationScheme, configureOptions);

        //注册中间件时使用，传入WXWorkOptions的DisplayName与WXWorkOptions
        public static AuthenticationBuilder AddWXWorkAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<WXWorkAuthenticationOptions> configureOptions)
            => builder.AddWXWorkAuthentication(authenticationScheme, WXWorkAuthenticationDefaults.DisplayName, configureOptions);
        
        //注册中间件时使用，传入WXWorkOptions的AauthenticationSchemeDisplayName与WXWorkOptions
        public static AuthenticationBuilder AddWXWorkAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<WXWorkAuthenticationOptions> configureOptions)
            => builder.AddOAuth<WXWorkAuthenticationOptions, WXWorAuthenticationkHandler>(authenticationScheme, displayName, configureOptions);
    }
}

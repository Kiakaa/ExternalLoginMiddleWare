using Microsoft.Extensions.DependencyInjection;
using System;

namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    public static class DingTalkExtensions
    {
        public static AuthenticationBuilder AddDingTalkAuthentication(this AuthenticationBuilder builder)
            => builder.AddDingTalkAuthentication(DingTalkAuthenticationDefaults.AuthenticationScheme, _ => { });

        //这里是入口
        public static AuthenticationBuilder AddDingTalkAuthentication(this AuthenticationBuilder builder, Action<DingTalkAuthenticationOptions> configureOptions)
            => builder.AddDingTalkAuthentication(DingTalkAuthenticationDefaults.AuthenticationScheme, configureOptions);

        public static AuthenticationBuilder AddDingTalkAuthentication(this AuthenticationBuilder builder, string authenticationScheme, Action<DingTalkAuthenticationOptions> configureOptions)
            => builder.AddDingTalkAuthentication(authenticationScheme, DingTalkAuthenticationDefaults.DisplayName, configureOptions);

        public static AuthenticationBuilder AddDingTalkAuthentication(this AuthenticationBuilder builder, string authenticationScheme, string displayName, Action<DingTalkAuthenticationOptions> configureOptions)
            => builder.AddOAuth<DingTalkAuthenticationOptions, DingTalkAuthenticationHandler>(authenticationScheme, displayName, configureOptions);
    }
}

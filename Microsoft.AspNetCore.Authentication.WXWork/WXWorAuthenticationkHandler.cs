using Microsoft.AspNetCore.Authentication.OAuth;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;
using System.Threading.Tasks;

namespace Microsoft.AspNetCore.Authentication.WXWork
{
    /// <summary>
    /// 企业微信第三方单点登录处理程序。
    /// 官网API说明：https://open.work.weixin.qq.com/api/old/doc#10991/%E4%BB%8E%E7%AC%AC%E4%B8%89%E6%96%B9%E5%8D%95%E7%82%B9%E7%99%BB%E5%BD%95
    /// </summary>
    internal class WXWorAuthenticationkHandler : OAuthHandler<WXWorkAuthenticationOptions>
    {
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="options">参数：包含ClientId、ClientSecret</param>
        /// <param name="logger">日志记录器</param>
        /// <param name="encoder"></param>
        /// <param name="clock"></param>
        public WXWorAuthenticationkHandler(IOptionsMonitor<WXWorkAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : 
            base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// 第一步：构造链接，引导用户进入登录授权页。
        /// </summary>
        /// <param name="properties">用于存储有关身份验证会话的状态值对象</param>
        /// <param name="redirectUri">跳转地址</param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            #region 内置浏览器判断
            // 判断当前请求是否由内置浏览器发出。可根据需要作限制是否只允许应用内访问(即不能直接通过浏览器访问)
            // 企业微信应用内置浏览器User Agetn标记：wxwork/2.4.99 MicroMessenger/6.3.22 Language/zh
            // 微信应用内置浏览器User Agetn标记：Safari/8536.25 MicroMessenger/6.1.0
            //var isMicroMessenger = Request.Headers[HeaderNames.UserAgent].ToString().ToLower().Contains("micromessenger");
            #endregion

            /**构造链接参数说明
             * 
                参数	    是否必须	说明
                appid	       是	    服务商的CorpID
                redirect_uri   是	    重定向地址。所在域名需要与授权完成回调域名一致，必填。
                state	       否	    用于防止重放攻击，选填
                usertype	   否	    支持登录的类型。admin代表管理员登录（使用微信扫码）,member代表成员登录（使用企业微信扫码），默认为admin
             */
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
            {
                ["appid"] = Options.ClientId,
                ["usertype"] = "member",
                ["redirect_uri"] = redirectUri,
                ["state"] = Options.StateDataFormat.Protect(properties)
            });
        }


        #region 处理远端认证结果（腾讯的企业微信认证服务器认证结果）
        /// <summary>
        /// 处理远端认证结果
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            #region 步骤1，验证会话是否一致，防止CSRF攻击
            // 用于存储有关身份验证会话的状态值对象
            AuthenticationProperties properties = null;
            var query = Request.Query;

            // 企业微信授权后会在redirectUri添加参数：redirect_url?auth_code=xxx
            var code = query["auth_code"];  //企业微信用户点授权码
            var state = query["state"];     //状态码
            var appid = query["appid"];     //供应商的corpid
            properties = Options.StateDataFormat.Unprotect(state);
            if (properties == null)
            {
                return HandleRequestResult.Fail("The oauth state was missing or invalid.");
            }

            // OAuth2 10.12 CSRF
            if (!ValidateCorrelationId(properties))
            {
                return HandleRequestResult.Fail("Correlation failed.");
            }

            if (StringValues.IsNullOrEmpty(code)) //code为null就是
            {
                return HandleRequestResult.Fail("Code was not found.");
            }
            #endregion


            #region 步骤2，使用服务提供商的coprid和ProviderSecret，取得供应商Token：provider_access_token，再使用此provider_access_token+用户授权码auth_code获取用户基本信息
            // 此处tokens为供应商的provider_access_token
            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }
            //由于企业微信单点登录使用点AccessToken是供应商(单点登录供应商)点Provider_Token，在此处ExchangeCodeAsync实际并不需要code，此code是用户授权码，此授权码+Provider_Token来后去用户基本信息。
            #region 获取provider_access_token的数据格式：
            /* 
                 {{
                    "provider_access_token": "BJdzC5e34p5sLY0Y8JRPnkhGyiUz6c1XtQCvRSmse4OA3hjNSqpLFE5qgsMUtjf-EXwUJKt5rFW0oLvQlNn1TFmIw9IIGbY6dYp-9vjaP_clbjekZhTMcpWEPgcH9Od_",
                    "expires_in": 7200
                    }}
                 */
            #endregion
            tokens.AccessToken = tokens.Response["provider_access_token"]?.ToString();
            tokens.ExpiresIn = tokens.Response["expires_in"]?.ToString();
            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            } 
            #endregion

            // 初始化一个Identity。有了auth_code和provider_access_token，下一步就是取用户基本信息。ClaimsIssuer：声明发行者
            var identity = new ClaimsIdentity(ClaimsIssuer);

            // 是否保存Token到用户身份验证会话中。可在注册中间件时或认证配置项中设置
            if (Options.SaveTokens)
            {
                var authTokens = new List<AuthenticationToken>();
                authTokens.Add(new AuthenticationToken { Name = "access_token", Value = tokens.AccessToken });
                if (!string.IsNullOrEmpty(tokens.RefreshToken))
                {
                    authTokens.Add(new AuthenticationToken { Name = "refresh_token", Value = tokens.RefreshToken });
                }
                if (!string.IsNullOrEmpty(tokens.TokenType))
                {
                    authTokens.Add(new AuthenticationToken { Name = "token_type", Value = tokens.TokenType });
                }
                if (!string.IsNullOrEmpty(tokens.ExpiresIn))
                {
                    int value;
                    if (int.TryParse(tokens.ExpiresIn, NumberStyles.Integer, CultureInfo.InvariantCulture, out value))
                    {
                        // https://www.w3.org/TR/xmlschema-2/#dateTime
                        // https://msdn.microsoft.com/en-us/library/az4se3k1(v=vs.110).aspx
                        var expiresAt = Clock.UtcNow + TimeSpan.FromSeconds(value);
                        authTokens.Add(new AuthenticationToken
                        {
                            Name = "expires_at",
                            Value = expiresAt.ToString("o", CultureInfo.InvariantCulture)
                        });
                    }
                }
                properties.StoreTokens(authTokens);
            }

            #region 步骤3，创建认证票据
            var ticket = await CreateTicketAsync(identity, properties, tokens);
            if (ticket != null)
            {
                //返回成功认证
                return HandleRequestResult.Success(ticket);
            }
            else
            {
                //返回失败认证
                return HandleRequestResult.Fail("Failed to retrieve user information from remote server.");
            } 
            #endregion
        }
        #endregion

        /// <summary>
        /// 第二步：获取供应商provider_access_token。获取使用使用服务供应商coprid和ProviderSecret，获取供应商的provider_access_token
        /// </summary>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            //1，设置post参数。获取供应商provider_access_token需要的post参数
            Dictionary<string, string> param = new Dictionary<string, string>();
            param.Add("corpid", Options.ClientId);
            param.Add("provider_secret", Options.ClientSecret);

            var stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");
            //2，发送请求并取得数据
            var response = await Backchannel.PostAsync(Options.TokenEndpoint, stringContent);
            //3，判断provider_access_token是否获取成功
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }
            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.Value<string>("errcode")))
            {
                Logger.LogError("An error occurred while retrieving an access token: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                return OAuthTokenResponse.Failed(new Exception("An error occurred while retrieving an access token."));
            }
            return OAuthTokenResponse.Success(payload);
        }

        /// <summary>
        ///  第三步：获取用户个人信息。创建远端服务器(企业微信认证服务器)认证票据
        /// </summary>
        /// <param name="identity">用户身份声明</param>
        /// <param name="properties">身份验证会话相关状态值</param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            #region 1， 请求参数配置
            var query = Request.Query;
            // 用户授权码。跟在redirectUri后。
            var code = query["auth_code"];
            // 获取用户基本信息的url参数:provider_access_token
            var address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
            });
            // 获取用户基本信息的post参数:用户授权码
            Dictionary<string, string> param = new Dictionary<string, string>();
            param.Add("auth_code", code);
            var stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");
            #endregion

            #region 2，发送请求并取得数据
            var response = await Backchannel.PostAsync(address, stringContent);
            #endregion

            #region 判断请求是否成功
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            if (!string.IsNullOrEmpty(payload.Value<string>("errcode")))
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }
            #endregion

            //3，提取响应内容中的user_info
            #region 响应内容格式
            /*
             *  {
             *     {
             *         "usertype": 5,
             *         "user_info": {
             *             "userid": "wangmaohai",
             *             "name": "王毛孩",
             *             "email": "kino@icloudengine.cn",
             *             "avatar": "http://p.qpic.cn/wwhead/nMl9ssowtibVGyrmvBiaibzDo5QicKNxARD52zpQ1kyQnOgvzzjYfaBhej0dnLqYtoyX5PbPgez1HmQ/0"
             *         },
             *         "corp_info": {
             *             "corpid": "ww4670356807022617"
             *         },
             *         "agent": []
             *     }
             *  }
             */
            #endregion
            LoginUserInfoDTO loginUserInfoDTO = WXWorkAuthenticationHelper.GetLoginUserInfo(payload);
            //4，从获取到的用户基本信息中，配置用户身份声明信息
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, loginUserInfoDTO.UserId, Options.ClaimsIssuer));//此行为必须项，没有NameIdentitier，会被认为用户未登录。
            identity.AddClaim(new Claim(ClaimTypes.Name, loginUserInfoDTO.Name, Options.ClaimsIssuer));
            identity.AddClaim(new Claim(ClaimTypes.Email, loginUserInfoDTO.Email, Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:wxwork:userid",loginUserInfoDTO.UserId, Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:wxwork:usertype", WXWorkAuthenticationHelper.GetUserType(payload), Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:wxwork:userinfo", WXWorkAuthenticationHelper.GetUserInfo(payload), Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:wxwork:avatar", loginUserInfoDTO.Avatar, Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:wxwork:agent", WXWorkAuthenticationHelper.GetAgent(payload), Options.ClaimsIssuer));
            //5，初始化一个OAuth正在创建ticket的上下文
            var context = new OAuthCreatingTicketContext(new ClaimsPrincipal(identity), properties, Context, Scheme, Options, Backchannel, tokens, payload);
            context.RunClaimActions();
            //6，Events：OAuthEvents。Handler调用事件上的方法，这些方法（在发生处理的某些点上（提供对应用程序）的控制）
            //   CreatingTicket：在提供程序成功验证用户后调用。
            //   context：包含有关登录会话以及用户System.Security.Claims.ClaimsIdentity(身份声明)的信息。
            await Events.CreatingTicket(context);
            //7，返回认证票据
            return new AuthenticationTicket(context.Principal, context.Properties, Scheme.Name);
        }
    }
}

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

namespace Microsoft.AspNetCore.Authentication.DingTalk
{
    /// <summary>
    /// 请求供应商AccessToken反序列化对象格式
    /// </summary>
    public class ProviderTokenDTO
    {
        /// <summary>
        /// 错误码
        /// </summary>
        public int ErrCode { get; set; }
        /// <summary>
        /// 错误消息
        /// </summary>
        public string ErrMsg { get; set; }
        /// <summary>
        /// 供应商AccessToken
        /// </summary>
        public string Provider_Access_Token { get; set; }
        /// <summary>
        /// 有效期。单位：秒
        /// </summary>
        public int Expires_In { get; set; }
    }
    /// <summary>
    /// 阿里钉钉扫码登录处理程序。
    /// 官网链接：https://open-doc.dingtalk.com/docs/doc.htm?spm=a219a.7629140.0.0.56754a97ywHpyb&treeId=168&articleId=104882&docType=1
    /// </summary>
    internal class DingTalkAuthenticationHandler : OAuthHandler<DingTalkAuthenticationOptions>
    {
        /// <summary>
        /// 构造函数
        /// </summary>
        /// <param name="options">参数：包含ClientId、ClientSecret</param>
        /// <param name="logger">日志记录器</param>
        /// <param name="encoder"></param>
        /// <param name="clock"></param>
        public DingTalkAuthenticationHandler(IOptionsMonitor<DingTalkAuthenticationOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock)
            : base(options, logger, encoder, clock)
        { }

        /// <summary>
        /// 第一步：构造链接，引导用户进入登录授权页。
        /// </summary>
        /// <param name="properties">用于存储有关身份验证会话的状态值对象</param>
        /// <param name="redirectUri">跳转地址</param>
        /// <returns></returns>
        protected override string BuildChallengeUrl(AuthenticationProperties properties, string redirectUri)
        {
            //登录授权链接格式：
            //https://oapi.dingtalk.com/connect/qrconnect?appid=APPID&response_type=code&scope=snsapi_login&state=STATE&redirect_uri=REDIRECT_URI

            /**构造链接参数说明
             * 
                参数	    是否必须	说明
                appid	       是	    阿里钉钉应用id
                response_type  是       固定为code，必填
                scope          是       固定为snsapi_login，必填
                state	       否	    用于防止重放攻击，选填
                redirect_uri   是	    重定向地址。该地址所在域名需要配置为appid对应的安全域名，必填
             */
            return QueryHelpers.AddQueryString(Options.AuthorizationEndpoint, new Dictionary<string, string>
            {
                ["appid"] = Options.ClientId,
                ["response_type"] = "code",
                ["scope"] = "snsapi_login",
                ["state"] = Options.StateDataFormat.Protect(properties),
                ["redirect_uri"] = redirectUri,
            });
        }


        #region 处理远端认证结果
        /// <summary>
        /// 处理远端认证结果（阿里钉钉认证服务器认证结果）
        /// </summary>
        /// <returns></returns>
        protected override async Task<HandleRequestResult> HandleRemoteAuthenticateAsync()
        {
            #region 步骤1，验证会话是否一致
            // 用于存储有关身份验证会话的状态值对象
            AuthenticationProperties properties = null;
            var query = Request.Query;

            // 阿里钉钉授权后会在redirectUri添加参数：redirect_url?auth_code=xxx
            var code = query["code"];  //用户授权给钉钉开放应用的免登授权码，第一步中获取的code
            var state = query["state"];     //状态码
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

            if (StringValues.IsNullOrEmpty(code))
            {
                return HandleRequestResult.Fail("Code was not found.");
            }
            #endregion

            #region 步骤2，通过appid,appsecret换取access_token地址。
            var tokens = await ExchangeCodeAsync(code, BuildRedirectUri(Options.CallbackPath));
            if (tokens.Error != null)
            {
                return HandleRequestResult.Fail(tokens.Error);
            }
            //tokens.AccessToken = tokens.Response["provider_access_token"]?.ToString();
            //tokens.ExpiresIn = tokens.Response["expires_in"]?.ToString();
            if (string.IsNullOrEmpty(tokens.AccessToken))
            {
                return HandleRequestResult.Fail("Failed to retrieve access token.");
            } 
            #endregion

            // 初始化一个Identity。有了auth_code和provider_access_token，下一步就是取用户基本信息。ClaimsIssuer：声明发行者
            var identity = new ClaimsIdentity(ClaimsIssuer);
            // 是否保存Token到用户身份验证会话中。
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
        /// 第二步：通过appid,appsecret换取access_token地址
        /// </summary>
        protected override async Task<OAuthTokenResponse> ExchangeCodeAsync(string code, string redirectUri)
        {
            //1，设置url get请求参数
            var address = QueryHelpers.AddQueryString(Options.TokenEndpoint, new Dictionary<string, string>()
            {
                ["appid"] = Options.ClientId,
                ["appsecret"] = Options.ClientSecret
            });
            //2，发送请求并取得数据
            var response = await Backchannel.GetAsync(address);
            //3，判断access_token是否获取成功
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
            if (!(payload.Value<int>("errcode")==0))
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
        ///  第五步：获取用户个人信息。创建远端服务器(企业微信认证服务器)认证票据
        /// </summary>
        /// <param name="identity">用户身份声明</param>
        /// <param name="properties">身份验证会话相关状态值</param>
        /// <param name="tokens"></param>
        /// <returns></returns>
        protected override async Task<AuthenticationTicket> CreateTicketAsync(ClaimsIdentity identity, AuthenticationProperties properties, OAuthTokenResponse tokens)
        {
            var query = Request.Query;
            // 用户临时授权码。跟在redirectUri后。
            var code = query["code"];

            #region 第三步：获取持久授权码
            #region 1， 请求参数配置
            var address = QueryHelpers.AddQueryString(DingTalkAuthenticationDefaults.PersistentTokenEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
            });

            // 获取用户基本信息的post参数:用户授权码
            Dictionary<string, string> param = new Dictionary<string, string>();
            param.Add("tmp_auth_code", code);
            var stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");
            #endregion

            #region 2，发送请求并取得数据
            var response = await Backchannel.PostAsync(address, stringContent);
            #endregion
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the persistent code: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving persistent code.");

            }
            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            if (!(payload.Value<int>("errcode") == 0))
            {
                Logger.LogError("An error occurred while retrieving the persistent code: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving persistent code.");
            }

            PersistentCodeDTO persistentDodeDTO = DingTalkAuthenticationHelper.GetPersistentCodeInfo(payload);
            #endregion

            #region 第四步：获取SNS_TOKEN
            address = QueryHelpers.AddQueryString(DingTalkAuthenticationDefaults.SNSTokenEndpoint, new Dictionary<string, string>
            {
                ["access_token"] = tokens.AccessToken,
            });

            // 获取用户基本信息的post参数:用户授权码
            param = new Dictionary<string, string>();
            param.Add("openid", persistentDodeDTO.OpenId);
            param.Add("persistent_code", persistentDodeDTO.Persistent_Code);
            stringContent = new StringContent(JsonConvert.SerializeObject(param), Encoding.UTF8, "application/json");

            #region 2，发送请求并取得数据
            response = await Backchannel.PostAsync(address, stringContent);
            #endregion
            if (!response.IsSuccessStatusCode)
            {
                Logger.LogError("An error occurred while retrieving the SNS_TOKEN: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving SNS_TOKEN.");

            }
            payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            if (!(payload.Value<int>("errcode") == 0))
            {
                Logger.LogError("An error occurred while retrieving the SNS_TOKEN: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving SNS_TOKEN.");
            }

            SNSTokenDTO snsTokenDTO = DingTalkAuthenticationHelper.GetSNSTokenInfo(payload);
            #endregion

            #region 第五步：使用SNS_TOKEN获取用户个人信息
            address = QueryHelpers.AddQueryString(Options.UserInformationEndpoint, new Dictionary<string, string>
            {
                ["sns_token"] = snsTokenDTO.SNS_Token,
            });

            #region 2，发送请求并取得数据
            response = await Backchannel.GetAsync(address);
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

            payload = JObject.Parse(await response.Content.ReadAsStringAsync());
            if (!(payload.Value<int>("errcode") == 0))
            {
                Logger.LogError("An error occurred while retrieving the user profile: the remote server " +
                                "returned a {Status} response with the following payload: {Headers} {Body}.",
                                /* Status: */ response.StatusCode,
                                /* Headers: */ response.Headers.ToString(),
                                /* Body: */ await response.Content.ReadAsStringAsync());

                throw new HttpRequestException("An error occurred while retrieving user information.");
            }
            #endregion
            #endregion
            //3，提取响应内容中的user_info
            #region 响应内容格式
            /*
             * { 
             *     "errcode": 0,
             *     "errmsg": "ok",
             *     "user_info": {
             *         "maskedMobile": "130****1234",
             *         "nick": "张三",
             *         "openid": "liSii8KCxxxxx",
             *         "unionid": "7Huu46kk"
             *     }
             * }
             */
            #endregion
            LoginUserInfoDTO loginUserInfoDTO = DingTalkAuthenticationHelper.GetLoginUserInfo(payload);
            
            //4，从获取到的用户基本信息中，配置用户身份声明信息
            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, loginUserInfoDTO.OpenId, Options.ClaimsIssuer));//此行为必须项，没有NameIdentitier，会被认为用户未登录。
            identity.AddClaim(new Claim(ClaimTypes.Name, loginUserInfoDTO.Nick, Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:dingtalk:unionid", loginUserInfoDTO.UnionId, Options.ClaimsIssuer));
            identity.AddClaim(new Claim("urn:dingtalk:userinfo", DingTalkAuthenticationHelper.GetUserInfo(payload), Options.ClaimsIssuer));
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

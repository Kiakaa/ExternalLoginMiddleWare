using Newtonsoft.Json.Linq;

namespace Microsoft.AspNetCore.Authentication.WXWork
{
    #region 响应内容格式
    //{
    //    {
    //        "usertype": 5,
    //        "user_info": {
    //            "userid": "wangmaohai",
    //            "name": "王毛孩",
    //            "email": "kino@icloudengine.cn",
    //            "avatar": "http://p.qpic.cn/wwhead/nMl9ssowtibVGyrmvBiaibzDo5QicKNxARD52zpQ1kyQnOgvzzjYfaBhej0dnLqYtoyX5PbPgez1HmQ/0"
    //        },
    //        "corp_info": {
    //            "corpid": "ww4670356807022617"
    //        },
    //        "agent": []
    //    }
    // }
    #endregion
    /// <summary>
    /// 获取用户基本信息后，反序列化userinfo的对象类别。
    /// </summary>
    public class LoginUserInfoDTO
    {
        public string UserId { get; set; }
        public string Name { get; set; }
        public string Email { get; set; }
        public string Avatar { get; set; }
    }

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
    /// 帮助类，获取JObject对象中的信息 <see cref="JObject"/>
    /// </summary>
    static class WXWorkAuthenticationHelper
    {
        /// <summary>
        /// 获取登录用户的类型：1.创建者 2.内部系统管理员 3.外部系统管理员 4.分级管理员 5.成员
        /// </summary>
        public static string GetUserType(JObject user) => user.Value<string>("usertype");

        /// <summary>
        /// 获取登录用户的信息.
        /// </summary>
        public static string GetUserInfo(JObject user) => user["user_info"].ToString();

        /// <summary>
        /// 获取登录用户信息的反序列化对象
        /// </summary>
        public static LoginUserInfoDTO GetLoginUserInfo(JObject user)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<LoginUserInfoDTO>(user["user_info"].ToString());
        }

        /// <summary>
        /// 获取授权方企业id
        /// </summary>
        public static string GetCorpInfo(JObject user) => user.Value<string>("corp_info");

        /// <summary>
        /// 获取该管理员在该提供商中能使用的应用列表，当登录用户为管理员时返回
        /// </summary>
        public static string GetAgent(JObject user)
        {
            var value = user.Value<JArray>("agent");
            if (value == null)
            {
                return null;
            }
            return string.Join(",", value.ToObject<string[]>());
        }
    }
}
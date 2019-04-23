using Newtonsoft.Json.Linq;

namespace Microsoft.AspNetCore.Authentication.DingTalk
{

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

    /// <summary>
    /// 用户授权的持久授权码反序列化对象类别
    /// </summary>
    public class PersistentCodeDTO
    {
        /// <summary>
        /// 错误码
        /// </summary>
        public int ErrCode { get; set; }
        /// <summary>
        /// 错误描述
        /// </summary>
        public string ErrMsg { get; set; }
        /// <summary>
        /// 用户在当前开放应用内的唯一标识
        /// </summary>
        public string OpenId { get; set; }
        /// <summary>
        /// 用户给开放应用授权的持久授权码，此码目前无过期时间
        /// </summary>
        public string Persistent_Code { get; set; }
        /// <summary>
        /// 用户在当前钉钉开放平台账号范围内的唯一标识，同一个钉钉开放平台账号可以包含多个开放应用，同时也包含ISV的套件应用及企业应用
        /// </summary>
        public string UnionId { get; set; }
    }

    /// <summary>
    /// 用户授权的SNS_TOKEN反序列化对象类别
    /// </summary>
    public class SNSTokenDTO
    {
        /// <summary>
        /// 错误码
        /// </summary>
        public int ErrCode { get; set; }
        /// <summary>
        /// 错误描述
        /// </summary>
        public string ErrMsg { get; set; }
        /// <summary>
        /// 用户在当前开放应用内的唯一标识
        /// </summary>
        public string SNS_Token { get; set; }
        /// <summary>
        /// 用户给开放应用授权的持久授权码，此码目前无过期时间
        /// </summary>
        public int Expires_In { get; set; }
    }
    /// <summary>
    /// 获取用户基本信息后，反序列化userinfo的对象类别。
    /// </summary>
    public class LoginUserInfoDTO
    {
        public string Nick { get; set; }
        public string OpenId { get; set; }
        public string UnionId { get; set; }
    }
    /// <summary>
    /// 成功获取用户基本信息后，从中获取数据帮助类 <see cref="JObject"/>
    /// </summary>
    static class DingTalkAuthenticationHelper
    {
        /// <summary>
        /// 获取登录用户的信息.
        /// </summary>
        public static string GetUserInfo(JObject user) => user["user_info"].ToString();

        /// <summary>
        /// 获取持续授权码反序列化对象
        /// </summary>
        public static PersistentCodeDTO GetPersistentCodeInfo(JObject jObject)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<PersistentCodeDTO>(jObject.ToString());
        }

        /// <summary>
        /// 获取持续授权码反序列化对象
        /// </summary>
        public static SNSTokenDTO GetSNSTokenInfo(JObject jObject)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<SNSTokenDTO>(jObject.ToString());
        }
        /// <summary>
        /// 获取登录用户信息的反序列化对象
        /// </summary>
        public static LoginUserInfoDTO GetLoginUserInfo(JObject user)
        {
            return Newtonsoft.Json.JsonConvert.DeserializeObject<LoginUserInfoDTO>(user["user_info"].ToString());
        }        
    }
}
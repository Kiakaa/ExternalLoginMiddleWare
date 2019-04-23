# Microsoft.AspNetCore.Authentication Extensions
 AspNetCore的 企业微信(WXWork)、阿里钉钉(DingTalk) 登录认证扩展


# Get Started

- 项目引用或安装nuget包
~~~
- WXWork   
~~~ json。配置信息
 //appsetting.json
 {
   //........其他配置
  "Authentication": {
    "WXWork": {
      "ClientId": "你的clientid（如果是供应商，填写供应商的corpid）",
      "ClientSecret":"你的clientsecret如果是供应商，填写供应商的ProviderSecret）"
    }
   }
  //........其他配置
 }

 
~~~ csharp
 // startup.cs 添加认证中间件
public void ConfigureServices(IServiceCollection services)
{
    // .... 其他代码 ...
    // config 
    services.AddAuthentication() 
        .AddWeixinAuthentication(options =>
        {
            options.ClientId = Configuration.GetValue<string>("Authentication:WXWork:ClientId");
            options.ClientSecret = Configuration.GetValue<string>("Authentication:Weixin:ClientSecret");
        });

    // .... 其他代码 ...
}
~~~   

用户确认登录并登录成功，获取外部登录信息. eg: AccountController
~~~  csharp
// GET: /Account/ExternalLoginCallback
[HttpGet]
[AllowAnonymous]
public async Task<IActionResult> ExternalLoginCallback(string returnUrl = null, string remoteError = null)
{ 
    // .... 其他代码 ...
    // .....
  
    // 从HttpContext获取登录者信息 (using Microsoft.AspNetCore.Authentication.WXWork;)
    var loginInfo = await HttpContext.GetExternalWXWorkLoginInfoAsync();
    
    // todo ...
    // .... 其他代码 ...
}
 
~~~
本地调试需要使用内网穿透技术，可借助穿透工具frp，frp使用说明链接：http://blog.abcenter.xyz/?p=41
frp项目地址：https://github.com/fatedier/frp/blob/master/README_zh.md
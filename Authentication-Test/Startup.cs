using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Authentication_Test.Data;
using Authentication_Test.Models;
using Authentication_Test.Services;
using Microsoft.AspNetCore.Authentication.WXWork;
using Microsoft.AspNetCore.Authentication.DingTalk;

namespace Authentication_Test
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(Configuration.GetConnectionString("DefaultConnection")));

            services.AddIdentity<ApplicationUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            // Add application services.
            services.AddTransient<IEmailSender, EmailSender>();
            //注册 认证中间件
            services.AddAuthentication()
                .AddQQAuthentication(options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:QQ:ClientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:QQ:ClientSecret");
                })
                .AddWeixinAuthentication(options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:Weixin:ClientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:Weixin:ClientSecret");

                })
                .AddWXWorkAuthentication(options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:WXWork:ClientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:WXWork:ClientSecret");
                })
                .AddDingTalkAuthentication(options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:DingTalk:ClientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:DingTalk:ClientSecret");
                }); ;

            services.AddMvc();

        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IHostingEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage(); 
                app.UseDatabaseErrorPage();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
            }

            app.UseStaticFiles();
            // 启用 认证中间件
            app.UseAuthentication();

            app.UseCookiePolicy();

            app.UseMvc(routes =>
            {
                routes.MapRoute(
                    name: "default",
                    template: "{controller=Home}/{action=Index}/{id?}");
            });
        }
    }
}

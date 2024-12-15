using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using AutoPartsApp.Models;
using AutoPartsApp.Context;
using AutoPartsApp.Models.User;
namespace AutoPartsApp
{
    public class Program
    {
        public static void Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);
            var connectionString = builder.Configuration.GetConnectionString("PostgresConnection") ?? throw new InvalidOperationException("Connection string 'AutoPartsAppContextConnection' not found.");

            builder.Services.AddDbContext<AutoPartsAppContext>(options => options.UseNpgsql(connectionString));

            builder.Services.AddIdentity<User, Role>()
                .AddEntityFrameworkStores<AutoPartsAppContext>()
                .AddDefaultTokenProviders();

            // Add services to the container.
            builder.Services.AddControllersWithViews();
            builder.Services.AddRazorPages();

            var app = builder.Build();

            // Configure the HTTP request pipeline.
            if (!app.Environment.IsDevelopment())
            {
                app.UseExceptionHandler("/Home/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");

            app.Run();
        }
    }
}

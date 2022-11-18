using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;

namespace Panzuto.AspNetCore.ApiAuth
{
    public static class DefaultJwtAuth
    {
        public static IServiceCollection AddDefaultJwtAuth(this IServiceCollection serviceCollection, IConfiguration configurationManager)
        {
            serviceCollection.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(configurationManager.GetConnectionString("ConnStr")));

            serviceCollection.AddIdentity<IdentityUser, IdentityRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            serviceCollection.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
                options.DefaultScheme = JwtBearerDefaults.AuthenticationScheme;
            }).AddJwtBearer(o =>
            {
                o.SaveToken = true;
                o.RequireHttpsMetadata = false;
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidIssuer = configurationManager["Jwt:Issuer"],
                    ValidAudience = configurationManager["Jwt:Audience"],
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configurationManager["Jwt:Key"])),
                    ValidateIssuer = true,
                    ValidateAudience = true,
                    ValidateLifetime = false,
                    ValidateIssuerSigningKey = true
                };
            });

            serviceCollection.AddAuthorization();

            return serviceCollection;
        }

        public static WebApplication AddDefaultJwtAuth(this WebApplication webApplication, ConfigurationManager? configurationManager)
        {
            JwtSecurityToken GetToken(List<Claim> authClaims)
            {
                var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configurationManager["Jwt:Key"]));

                var token = new JwtSecurityToken(
                    issuer: configurationManager["Jwt:Issuer"],
                    audience: configurationManager["Jwt:Audience"],
                    expires: DateTime.Now.AddHours(3),
                    claims: authClaims,
                    signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)
                );

                return token;
            }

            webApplication.UseAuthentication();
            webApplication.UseAuthorization();

            webApplication.MapPost("/api/authenticate/login",
                [AllowAnonymous] async (LoginModel model, UserManager<IdentityUser> userManager) =>
                {
                    var user = await userManager.FindByNameAsync(model.Username);

                    if (user != null && await userManager.CheckPasswordAsync(user, model.Password))
                    {
                        var userRoles = await userManager.GetRolesAsync(user);

                        var authClaims = new List<Claim>
                        {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                        };

                        foreach (var userRole in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                        }

                        var token = GetToken(authClaims);

                        return Results.Ok(new
                        {
                            token = new JwtSecurityTokenHandler().WriteToken(token),
                            expiration = token.ValidTo
                        });
                    }

                    return Results.Unauthorized();
                });

            webApplication.MapPost("/api/authenticate/register",
                [AllowAnonymous] async (RegisterModel model, UserManager<IdentityUser> userManager) =>
                {
                    var userExists = await userManager.FindByNameAsync(model.Username);
                    if (userExists != null)
                        return Results.StatusCode(StatusCodes.Status500InternalServerError);
                    //return Results.StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

                    IdentityUser user = new()
                    {
                        Email = model.Email,
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = model.Username
                    };
                    var result = await userManager.CreateAsync(user, model.Password);
                    if (!result.Succeeded)
                        return Results.StatusCode(StatusCodes.Status500InternalServerError);
                    //return Results.StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    return Results.Ok(new Response { Status = "Success", Message = "User created successfully!" });
                });

            webApplication.MapPost("/api/authenticate/register-admin",
                [AllowAnonymous] async (RegisterModel model, UserManager<IdentityUser> userManager,
                    RoleManager<IdentityRole> roleManager) =>
                {
                    var userExists = await userManager.FindByNameAsync(model.Username);
                    if (userExists != null)
                        return Results.StatusCode(StatusCodes.Status500InternalServerError);
                    //return Results.StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User already exists!" });

                    IdentityUser user = new()
                    {
                        Email = model.Email,
                        SecurityStamp = Guid.NewGuid().ToString(),
                        UserName = model.Username
                    };
                    var result = await userManager.CreateAsync(user, model.Password);
                    if (!result.Succeeded)
                        return Results.StatusCode(StatusCodes.Status500InternalServerError);
                    //return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

                    if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
                        await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
                    if (!await roleManager.RoleExistsAsync(UserRoles.User))
                        await roleManager.CreateAsync(new IdentityRole(UserRoles.User));

                    if (await roleManager.RoleExistsAsync(UserRoles.Admin))
                    {
                        await userManager.AddToRoleAsync(user, UserRoles.Admin);
                    }

                    if (await roleManager.RoleExistsAsync(UserRoles.Admin))
                    {
                        await userManager.AddToRoleAsync(user, UserRoles.User);
                    }

                    return Results.Ok(new Response { Status = "Success", Message = "User created successfully!" });
                });

            return webApplication;
        }

    }
}
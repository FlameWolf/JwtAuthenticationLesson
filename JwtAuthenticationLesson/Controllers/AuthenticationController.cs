using JwtAuthenticationLesson.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace JwtAuthenticationLesson.Controllers
{
	[Route("api/[controller]")]
	[ApiController]
	public class AuthenticationController : ControllerBase
	{
		private readonly UserManager<ApplicationUser> userManager;
		private readonly RoleManager<IdentityRole> roleManager;
		private readonly IConfiguration configuration;

		public AuthenticationController
		(
			UserManager<ApplicationUser> _userManager,
			RoleManager<IdentityRole> _roleManager,
			IConfiguration _configuration
		)
		{
			userManager = _userManager;
			roleManager = _roleManager;
			configuration = _configuration;
		}

		[Route("login")]
		[HttpPost]
		public async Task<IActionResult> Login([FromBody] LoginModel model)
		{
			var user = await userManager.FindByNameAsync(model.Username);
			if((user != null) && await userManager.CheckPasswordAsync(user, model.Password))
			{
				var authClaims = new List<Claim>
				{
					new Claim(ClaimTypes.Name, user.UserName),
					new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
				};
				foreach (var userRole in await userManager.GetRolesAsync(user))
				{
					authClaims.Add(new Claim(ClaimTypes.Role, userRole));
				}
				var jwtSecurityToken = new JwtSecurityToken
				(
					configuration["Jwt:ValidIssuer"],
					configuration["Jwt:ValidAudience"],
					authClaims,
					DateTime.Now,
					DateTime.Now.AddMinutes(20),
					new SigningCredentials
					(
						new SymmetricSecurityKey
						(
							Encoding.UTF8.GetBytes(configuration["Jwt:Secret"])
						),
						SecurityAlgorithms.HmacSha256
					)
				);
				return Ok(new
				{
					token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
					expiration = jwtSecurityToken.ValidTo
				});
			}
			return Unauthorized();
		}

		[HttpPost]
		[Route("register")]
		public async Task<IActionResult> Register([FromBody] RegisterModel model)
		{
			if(await userManager.FindByNameAsync(model.UserName) == null)
			{
				ApplicationUser user = new ApplicationUser
				{
					Email = model.Email,
					UserName = model.UserName,
					SecurityStamp = Guid.NewGuid().ToString()
				};
				if (await userManager.CreateAsync(user, model.Password) != IdentityResult.Success)
				{
					return StatusCode
					(
						StatusCodes.Status500InternalServerError,
						new Response
						{
							Status = "Error",
							Message = "Failed to create user"
						}
					);
				}
				return Ok(new Response
				{
					Status = "Success",
					Message = "User created"
				});
			}
			return StatusCode
			(
				StatusCodes.Status409Conflict,
				new Response
				{
					Status = "Error",
					Message = "Username already exists"
				}
			);
		}

		[HttpPost]
		[Route("register-admin")]
		public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
		{
			if (await userManager.FindByNameAsync(model.UserName) == null)
			{
				ApplicationUser user = new ApplicationUser
				{
					Email = model.Email,
					UserName = model.UserName,
					SecurityStamp = Guid.NewGuid().ToString()
				};
				if (await userManager.CreateAsync(user, model.Password) != IdentityResult.Success)
				{
					return StatusCode
					(
						StatusCodes.Status500InternalServerError,
						new Response
						{
							Status = "Error",
							Message = "Failed to create user"
						}
					);
				}
				if (!await roleManager.RoleExistsAsync(UserRoles.Admin))
				{
					await roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));
				}
				if (!await roleManager.RoleExistsAsync(UserRoles.User))
				{
					await roleManager.CreateAsync(new IdentityRole(UserRoles.User));
				}
				await userManager.AddToRoleAsync(user, UserRoles.Admin);
				return Ok(new Response
				{
					Status = "Success",
					Message = "Admin user created"
				});
			}
			return StatusCode
			(
				StatusCodes.Status409Conflict,
				new Response
				{
					Status = "Error",
					Message = "Username already exists"
				}
			);
		}
	}
}
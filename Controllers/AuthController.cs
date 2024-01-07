using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthWebApi.Core.Constants;
using JwtAuthWebApi.Core.DTOs;
using JwtAuthWebApi.Core.Entities;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthWebApi.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;
    public AuthController(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
    {
        _roleManager = roleManager;
        _userManager = userManager;
        _configuration = configuration;
    }

    // Route for seedinf roles to the DB
    [HttpPost]
    [Route("seed-roles")]
    public async Task<IActionResult> SeedRoles()
    {
        bool ownerRoleExists = await _roleManager.RoleExistsAsync(UserRoles.OWNER);
        bool adminRoleExists = await _roleManager.RoleExistsAsync(UserRoles.ADMIN);
        bool userRoleExists = await _roleManager.RoleExistsAsync(UserRoles.USER);

        if (ownerRoleExists && adminRoleExists && userRoleExists)
        {
            return Ok("Roles Seeding Already Done");
        }

        await _roleManager.CreateAsync(new IdentityRole(UserRoles.OWNER));
        await _roleManager.CreateAsync(new IdentityRole(UserRoles.ADMIN));
        await _roleManager.CreateAsync(new IdentityRole(UserRoles.USER));

        return Ok("Roles Seeding Done Successfully");
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        var userExists = await _userManager.FindByNameAsync(registerDto.UserName);
        if (userExists != null)
        {
            return StatusCode(StatusCodes.Status409Conflict, "User already exists!");
        }

        ApplicationUser user = new()
        {
            UserName = registerDto.UserName,
            FirstName = registerDto.FirstName,
            LastName = registerDto.LastName,
            Email = registerDto.Email,
            SecurityStamp = Guid.NewGuid().ToString(),

        };

        var result = await _userManager.CreateAsync(user, registerDto.Password);
        if (!result.Succeeded)
        {
            var errorString = new StringBuilder("User creation Failed Because: ");
            foreach (var error in result.Errors)
            {
                errorString.Append(error.Description + " ");
            }
            return StatusCode(StatusCodes.Status500InternalServerError, errorString.ToString());
        }

        // Assigning the user to the USER role by default
        await _userManager.AddToRoleAsync(user, UserRoles.USER);

        return Ok("User Created Successfully");
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        var user = await _userManager.FindByNameAsync(loginDto.UserName);
        if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            return Unauthorized("Invalid Username or Password");
        }

        // create a the jwt token
        var token = await CreateJsonWebToken(user);

        return Ok(token);
    }

    private async Task<string> CreateJsonWebToken(ApplicationUser user)
    {
        var roles = await _userManager.GetRolesAsync(user);

        var authClaims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, user.UserName!),
            new Claim(ClaimTypes.NameIdentifier, user.Id!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim("FirstName", user.FirstName!),
            new Claim("LastName", user.LastName!),
        };

        foreach (var role in roles)
        {
            authClaims.Add(new Claim(ClaimTypes.Role, role));
        }

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["Jwt:Secret"]!));

        var authCreds = new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha512Signature);
        var token = new JwtSecurityToken(
            issuer: _configuration["Jwt:Issuer"],
            audience: _configuration["Jwt:Audience"],
            expires: DateTime.Now.AddSeconds(_configuration.GetValue<int>("Jwt:ExpirationInSeconds")),
            claims: authClaims,
            signingCredentials: authCreds
        );

        var tokenHandler = new JwtSecurityTokenHandler();

        return tokenHandler.WriteToken(token);
    }

    // Make user an admin
    [Authorize]
    [HttpPost]
    [Route("make-admin")]
    public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user == null)
        {
            return NotFound("User Not Found");
        }

        await _userManager.AddToRoleAsync(user, UserRoles.ADMIN);

        return Ok("User is now an Admin");
    }

    // Make user an owner
    [Authorize]
    [HttpPost]
    [Route("make-owner")]
    public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user == null)
        {
            return NotFound("User Not Found");
        }

        await _userManager.AddToRoleAsync(user, UserRoles.OWNER);

        return Ok("User is now an Owner");
    }
}

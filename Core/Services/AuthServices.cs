using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using JwtAuthWebApi.Core.Constants;
using JwtAuthWebApi.Core.DTOs;
using JwtAuthWebApi.Core.Entities;
using JwtAuthWebApi.Core.Interfaces;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace JwtAuthWebApi.Core.Services;

class AuthService : IAuthService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly IConfiguration _configuration;

    public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    public async Task<AuthServiceResponseDto> SeedRolesAsync()
    {
        bool ownerRoleExists = await _roleManager.RoleExistsAsync(UserRoles.OWNER);
        bool adminRoleExists = await _roleManager.RoleExistsAsync(UserRoles.ADMIN);
        bool userRoleExists = await _roleManager.RoleExistsAsync(UserRoles.USER);

        if (ownerRoleExists && adminRoleExists && userRoleExists)
        {
            return new AuthServiceResponseDto
            {
                IsSuccess = true,
                Message = "Roles Seeding Already Done",
            };
        }

        await _roleManager.CreateAsync(new IdentityRole(UserRoles.OWNER));
        await _roleManager.CreateAsync(new IdentityRole(UserRoles.ADMIN));
        await _roleManager.CreateAsync(new IdentityRole(UserRoles.USER));

        return new AuthServiceResponseDto
        {
            IsSuccess = true,
            Message = "Roles Seeding Done Successfully",
        };
    }

    public async Task<AuthServiceResponseDto> RegisterAsync(RegisterDto registerDto)
    {
        var userExists = await _userManager.FindByNameAsync(registerDto.UserName);
        if (userExists != null)
        {
            return new AuthServiceResponseDto
            {
                IsSuccess = false,
                Message = "User already exists!",
            };
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
            return new AuthServiceResponseDto
            {
                IsSuccess = false,
                Message = errorString.ToString(),
            };
        }

        // Assigning the user to the USER role by default
        await _userManager.AddToRoleAsync(user, UserRoles.USER);

        return new AuthServiceResponseDto
        {
            IsSuccess = true,
            Message = "User created successfully",
        };
    }

    public async Task<AuthServiceResponseDto> LoginAsync(LoginDto loginDto)
    {
        var user = await _userManager.FindByNameAsync(loginDto.UserName);
        if (user == null || !await _userManager.CheckPasswordAsync(user, loginDto.Password))
        {
            return new AuthServiceResponseDto
            {
                IsSuccess = false,
                Message = "Invalid Login Credentials",
            };
        }

        // create a the jwt token
        var token = await CreateJsonWebToken(user);

        return new AuthServiceResponseDto
        {
            IsSuccess = true,
            Message = token
        };
    }

    public async Task<AuthServiceResponseDto> MakeAdminAsync(UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user == null)
        {
            return new AuthServiceResponseDto
            {
                IsSuccess = false,
                Message = "User Not Found",
            };
        }

        await _userManager.AddToRoleAsync(user, UserRoles.ADMIN);

        return new AuthServiceResponseDto
        {
            IsSuccess = true,
            Message = "User is now an Admin",
        };
    }

    public async Task<AuthServiceResponseDto> MakeOwnerAsync(UpdatePermissionDto updatePermissionDto)
    {
        var user = await _userManager.FindByNameAsync(updatePermissionDto.UserName);
        if (user == null)
        {
            return new AuthServiceResponseDto
            {
                IsSuccess = false,
                Message = "User Not Found",
            };
        }

        await _userManager.AddToRoleAsync(user, UserRoles.OWNER);

        return new AuthServiceResponseDto
        {
            IsSuccess = true,
            Message = "User is now an Owner",
        };
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
}
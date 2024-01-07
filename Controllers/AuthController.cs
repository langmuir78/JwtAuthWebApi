using JwtAuthWebApi.Core.DTOs;
using JwtAuthWebApi.Core.Interfaces;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthWebApi.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    private readonly IAuthService _authService;

    public AuthController(IAuthService authService)
    {
        _authService = authService;
    }

    // Route for seedinf roles to the DB
    [HttpPost]
    [Route("seed-roles")]
    public async Task<IActionResult> SeedRoles()
    {
        var seedResult = await _authService.SeedRolesAsync();
        if (!seedResult.IsSuccess)
        {
            return Unauthorized(seedResult.Message);
        }

        return Ok(seedResult.Message);
    }

    [HttpPost]
    [Route("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto registerDto)
    {
        var registerResult = await _authService.RegisterAsync(registerDto);
        if (!registerResult.IsSuccess)
        {
            return StatusCode(StatusCodes.Status500InternalServerError, registerResult.Message);
        }

        return Ok(registerResult.Message);
    }

    [HttpPost]
    [Route("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto loginDto)
    {
        var loginResult = await _authService.LoginAsync(loginDto);
        if (!loginResult.IsSuccess)
        {
            return Unauthorized(loginResult.Message);
        }

        return Ok(loginResult.Message);
    }

    // Make user an admin
    [Authorize]
    [HttpPost]
    [Route("make-admin")]
    public async Task<IActionResult> MakeAdmin([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var makeAdminResult = await _authService.MakeAdminAsync(updatePermissionDto);
        if (!makeAdminResult.IsSuccess)
        {
            return BadRequest(makeAdminResult.Message);
        }

        return Ok(makeAdminResult.Message);
    }

    // Make user an owner
    [Authorize]
    [HttpPost]
    [Route("make-owner")]
    public async Task<IActionResult> MakeOwner([FromBody] UpdatePermissionDto updatePermissionDto)
    {
        var makeOwnerResult = await _authService.MakeAdminAsync(updatePermissionDto);
        if (!makeOwnerResult.IsSuccess)
        {
            return BadRequest(makeOwnerResult.Message);
        }

        return Ok(makeOwnerResult.Message);
    }
}

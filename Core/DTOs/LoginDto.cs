using System.ComponentModel.DataAnnotations;

namespace JwtAuthWebApi.Core.DTOs;

public class LoginDto
{
    [Required(ErrorMessage = "Username is required")]
    public string UserName { get; set; } = null!;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = null!;
}
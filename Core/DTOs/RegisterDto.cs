using System.ComponentModel.DataAnnotations;

namespace JwtAuthWebApi.Core.DTOs;

public class RegisterDto
{
    [Required(ErrorMessage = "Username is required")]
    public string UserName { get; set; } = null!;

    [Required(ErrorMessage = "FirstName is required")]
    public string FirstName { get; set; } = null!;

    [Required(ErrorMessage = "LastName is required")]
    public string LastName { get; set; } = null!;

    [Required(ErrorMessage = "Email is required")]
    public string Email { get; set; } = null!;

    [Required(ErrorMessage = "Password is required")]
    public string Password { get; set; } = null!;
}
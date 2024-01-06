using System.ComponentModel.DataAnnotations;

namespace JwtAuthWebApi.Core.DTOs;

public class UpdatePermissionDto
{
    [Required(ErrorMessage = "Username is required")]
    public string UserName { get; set; } = null!;
}
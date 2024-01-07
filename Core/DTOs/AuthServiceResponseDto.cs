namespace JwtAuthWebApi.Core.DTOs;

public class AuthServiceResponseDto
{
    public bool IsSuccess { get; set; } = default!;
    public string Message { get; set; } = default!;
}

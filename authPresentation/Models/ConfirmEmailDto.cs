using System.ComponentModel.DataAnnotations;

namespace authPresentation.Models;

public class ConfirmEmailDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = null!;

    [Required]
    public string Code { get; set; } = null!;
}
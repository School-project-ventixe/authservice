using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using System.Net.Http.Json;
using System.Security.Claims;
using System.Text;
using authPresentation.Data.Entities;
using authPresentation.Extensions;
using authPresentation.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace authPresentation.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController(
    UserManager<AppUser> userManager,
    SignInManager<AppUser> signInManager,
    IConfiguration config,
    IHttpClientFactory httpClientFactory
) : ControllerBase
{
    private readonly UserManager<AppUser> _userManager = userManager;
    private readonly SignInManager<AppUser> _signInManager = signInManager;
    private readonly IConfiguration _config = config;
    private readonly IHttpClientFactory _httpClientFactory = httpClientFactory;

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegisterDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var existingUser = await _userManager.FindByEmailAsync(dto.Email);
        if (existingUser != null) return BadRequest("Email already in use");

        var user = dto.MapTo<AppUser>();
        user.UserName = dto.Email;

        var result = await _userManager.CreateAsync(user, dto.Password);
        if (!result.Succeeded) return BadRequest(result.Errors);

        try
        {
            var client = _httpClientFactory.CreateClient("VerificationService");

            await client.PostAsJsonAsync("verification/send", new
            {
                Email = dto.Email
            });
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Could not send verification email: {ex.Message}");
        }

        return Ok("Account created. Please verify your email.");
    }

    [HttpPost("confirm")]
    public async Task<IActionResult> ConfirmEmail([FromBody] ConfirmEmailDto dto)
    {
        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return NotFound("User not found");

        try
        {
            var client = _httpClientFactory.CreateClient("VerificationService");

            var response = await client.PostAsJsonAsync("verification/verify", new
            {
                Email = dto.Email,
                Code = dto.Code
            });

            if (!response.IsSuccessStatusCode)
                return BadRequest("Invalid or expired code");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"Verification service error: {ex.Message}");
            return StatusCode(500, "Verification service error");
        }

        user.EmailConfirmed = true;
        await _userManager.UpdateAsync(user);

        return Ok("Email confirmed successfully.");
    }

    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginDto dto)
    {
        if (!ModelState.IsValid) return BadRequest(ModelState);

        var user = await _userManager.FindByEmailAsync(dto.Email);
        if (user == null) return Unauthorized();

        if (!await _userManager.CheckPasswordAsync(user, dto.Password))
            return Unauthorized();

        if (!await _userManager.IsEmailConfirmedAsync(user))
            return Unauthorized("Please verify your email before logging in.");

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Email!),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.GivenName, user.FirstName),
            new Claim(ClaimTypes.Surname, user.LastName)
        };

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["JwtKey"]!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var jwt = new JwtSecurityToken(
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        var tokenStr = new JwtSecurityTokenHandler().WriteToken(jwt);

        Response.Cookies.Append("jwt", tokenStr, new CookieOptions
        {
            HttpOnly = true,
            Secure = true,
            SameSite = SameSiteMode.None,
            Expires = DateTimeOffset.UtcNow.AddHours(1)
        });

        return Ok();
    }

    [HttpPost("logout")]
    public IActionResult Logout()
    {
        Response.Cookies.Delete("jwt", new CookieOptions
        {
            Secure = true,
            SameSite = SameSiteMode.None
        });

        return Ok("Logged out");
    }

    [HttpGet("me")]
    [Authorize]
    public IActionResult Me()
    {
        var user = HttpContext.User;
        var firstName = user.FindFirst(ClaimTypes.GivenName)?.Value;
        var lastName = user.FindFirst(ClaimTypes.Surname)?.Value;
        var email = user.FindFirst(JwtRegisteredClaimNames.Sub)?.Value;

        return Ok(new
        {
            firstName,
            lastName,
            email
        });
    }
}

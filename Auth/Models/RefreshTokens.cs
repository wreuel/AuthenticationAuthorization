namespace Auth.Models
{
    public class RefreshTokens
    {
        public Guid Id { get; set; }
        public string UserId { get; set; }
        public string RefreshToken { get; set; }
        public DateTimeOffset ValidTo { get; set; }
    }
}

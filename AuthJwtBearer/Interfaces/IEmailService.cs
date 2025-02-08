using AuthJwtBearer.Models;

namespace AuthJwtBearer.Interfaces
{
    public interface IEmailService
    {
        Task Send(EmailModel emailData);
    }
}

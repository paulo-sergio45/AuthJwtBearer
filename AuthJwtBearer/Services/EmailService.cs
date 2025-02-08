using AuthJwtBearer.Interfaces;
using AuthJwtBearer.Models;
using MailKit.Net.Smtp;
using MailKit.Security;
using MimeKit;

namespace AuthJwtBearer.Services
{
    public class EmailService : IEmailService
    {
        private readonly IConfiguration _configuration;
        private string _serveReturn;
        public EmailService(IConfiguration configuration)
        {
            _configuration = configuration;
            _serveReturn = "";
        }
        public async Task Send(EmailModel emailData)
        {
            try
            {
                var message = new MimeMessage();
                message.From.Add(new MailboxAddress(_configuration["EmailSettings:Name"], _configuration["EmailSettings:Email"]));
                message.To.Add(new MailboxAddress(emailData.Name, emailData.ToAddress));
                message.Subject = emailData.Subject;

                message.Body = new TextPart("plain")
                {
                    Text = emailData.Body
                };

                using (var client = new SmtpClient())
                {
                    await client.ConnectAsync(_configuration["SMTPSetting:Host"], _configuration.GetValue<int>("SMTPSetting:Port"), SecureSocketOptions.StartTls);

                    var oauth2 = new SaslMechanismOAuth2(_configuration["SMTPSetting:ClientId"], _configuration["SMTPSetting:SMTPToken"]);

                    //await client.AuthenticateAsync(oauth2);

                    await client.AuthenticateAsync(_configuration["EmailSettings:Username"], _configuration["EmailSettings:Password"]);


                    _serveReturn = await client.SendAsync(message);

                    client.Disconnect(true);
                }
            }
            catch (Exception e)
            {
                throw new InvalidOperationException("Erro Message: " + _serveReturn, e);
            }
        }
    }
}

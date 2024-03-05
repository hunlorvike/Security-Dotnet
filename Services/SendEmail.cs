using System;
using System.Net;
using System.Net.Mail;

namespace CustomSecurityDotnet.Services
{
    public class SendEmail
    {
        // Use configuration or a secure storage mechanism for sensitive information
        private static readonly string HostAddress = "smtp.gmail.com";
        private static readonly string FromEmailId = "viethung0106.developer@gmail.com";
        private static readonly string Password = "xwkvhbfbfnhsgugl";
        private static readonly int Port = 587;

        protected SendEmail()
        {
        }

        public static bool EmailSend(string recipientEmail, string subject, string message, bool isBodyHtml = false)
        {
            bool status = false;
            try
            {
                MailMessage mailMessage = new MailMessage();
                mailMessage.From = new MailAddress(FromEmailId);
                mailMessage.Subject = subject;
                mailMessage.Body = message;
                mailMessage.IsBodyHtml = isBodyHtml;
                mailMessage.To.Add(new MailAddress(recipientEmail));

                using (SmtpClient smtp = new SmtpClient())
                {
                    smtp.Host = HostAddress;
                    smtp.Port = Port;
                    smtp.EnableSsl = true;

                    NetworkCredential networkCredential = new NetworkCredential();
                    networkCredential.UserName = mailMessage.From.Address;
                    networkCredential.Password = Password;
                    smtp.Credentials = networkCredential;

                    smtp.Send(mailMessage);
                }

                status = true;
                return status;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                return status;
            }
        }

    }
}

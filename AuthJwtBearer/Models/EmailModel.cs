namespace AuthJwtBearer.Models
{
    public class EmailModel
    {
        public required string ToAddress { get; set; }
        public string Name { get; set; }
        public required string Subject { get; set; }
        public string Body { get; set; }
        public string AttachmentPath { get; set; }

    }
}

namespace AuthJwtBearer.DTOs
{
    public class PasswordValidatorResponseDTO
    {
        public List<PasswordValidatorFailedDTO>? ListError { get; set; }
        public bool Result { get; set; }

    }
}

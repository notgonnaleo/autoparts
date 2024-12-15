namespace AutoPartsApp.Models.User.Request
{
    public class NewUserRequest
    {
        public string EmailAddress { get; set; }
        public string UserName { get; set; }
        public string PhoneNumber { get; set; }
        public string Password { get; set; }
    }
}

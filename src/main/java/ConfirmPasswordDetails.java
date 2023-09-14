public class ConfirmPasswordDetails {
    private String email;
    private String confirmationCode;
    private String newPassword;

    public String getEmail() {  // Renamed the getter to getEmail
        return email;
    }

    public void setEmail(String email) {  // Renamed the setter to setEmail
        this.email = email;
    }

    public String getConfirmationCode() {
        return confirmationCode;
    }

    public void setConfirmationCode(String confirmationCode) {
        this.confirmationCode = confirmationCode;
    }

    public String getNewPassword() {
        return newPassword;
    }

    public void setNewPassword(String newPassword) {
        this.newPassword = newPassword;
    }
}

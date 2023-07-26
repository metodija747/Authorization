import com.auth0.jwt.interfaces.DecodedJWT;
import com.google.gson.Gson;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.annotation.security.PermitAll;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;
import com.auth0.jwt.JWT;
import com.auth0.jwt.interfaces.DecodedJWT;

@Path("/authorization")
public class AuthorizationResource {
    private static final String USER_POOL_ID = "us-east-1_cl8iVMzUw";
    private static final String CLIENT_APP_ID = "16fec44qrgoth26a20ob5ft0tb";
    private String issuer = "https://cognito-idp.us-east-1.amazonaws.com/us-east-1_cl8iVMzUw";
    private CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
            .region(Region.US_EAST_1)
            .build();

    @POST
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response registerUser(UserDetails userDetails) {
        // Parse the event body into a map
        String email = userDetails.getEmail();
        String password = userDetails.getPassword();

        // Perform user registration logic
        try {
            // Create email attribute
            AttributeType emailAttribute = AttributeType.builder()
                    .name("email")
                    .value(email)
                    .build();

            SignUpRequest signUpRequest = SignUpRequest.builder()
                    .clientId(CLIENT_APP_ID)
                    .username(email)
                    .password(password)
                    .userAttributes(emailAttribute) // adding the attributes
                    .build();

            SignUpResponse signUpResponse = cognitoClient.signUp(signUpRequest);

            // Immediately confirm the user
            AdminConfirmSignUpRequest confirmSignUpRequest = AdminConfirmSignUpRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(email)
                    .build();

            cognitoClient.adminConfirmSignUp(confirmSignUpRequest);

            // Set email as verified
            AttributeType emailVerifiedAttribute = AttributeType.builder()
                    .name("email_verified")
                    .value("true") // setting email as verified
                    .build();

            AdminUpdateUserAttributesRequest updateUserAttributesRequest = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(email)
                    .userAttributes(emailVerifiedAttribute)
                    .build();

            cognitoClient.adminUpdateUserAttributes(updateUserAttributesRequest);

            return Response.ok("User registered successfully").build();
        } catch (CognitoIdentityProviderException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to register user: " + e.getMessage()).build();
        }
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    public Response loginUser(UserDetails userDetails) {
        String username = userDetails.getEmail();
        String password = userDetails.getPassword();

        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);

        InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(CLIENT_APP_ID)
                .authParameters(authParams)
                .build();

        try {
            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("accessToken", authResponse.authenticationResult().accessToken());
            responseBody.put("idToken", authResponse.authenticationResult().idToken());
            responseBody.put("RefreshToken", authResponse.authenticationResult().refreshToken());

            return Response.ok(responseBody).build();
        } catch (CognitoIdentityProviderException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.awsErrorDetails().errorMessage()).build();
        }
    }

    @POST
    @Path("/forgot-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response forgotPassword(@QueryParam("username") String Username) {
        AdminGetUserRequest adminGetUserRequest = AdminGetUserRequest.builder()
                .userPoolId(USER_POOL_ID)
                .username(Username)
                .build();
        try {
            cognitoClient.adminGetUser(adminGetUserRequest);
        } catch (UserNotFoundException e) {
            return Response.status(Response.Status.NOT_FOUND).entity("User with given email address does not exist.").build();
        }

        ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                .clientId(CLIENT_APP_ID)
                .username(Username)
                .build();
        try {
            cognitoClient.forgotPassword(forgotPasswordRequest);
            return Response.ok("Confirmation code sent to your email!").build();
        } catch (CognitoIdentityProviderException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.awsErrorDetails().errorMessage()).build();
        }
    }

    @POST
    @Path("/confirm-forgot-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    public Response confirmForgotPassword(ConfirmPasswordDetails passwordDetails) {
        String username = passwordDetails.getUsername();
        String confirmationCode = passwordDetails.getConfirmationCode();
        String newPassword = passwordDetails.getNewPassword();

        ConfirmForgotPasswordRequest confirmForgotPasswordRequest = ConfirmForgotPasswordRequest.builder()
                .clientId(CLIENT_APP_ID)
                .username(username)
                .confirmationCode(confirmationCode)
                .password(newPassword)
                .build();

        try {
            cognitoClient.confirmForgotPassword(confirmForgotPasswordRequest);
            return Response.ok("Password changed successfully").build();
        } catch (CognitoIdentityProviderException e) {
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity(e.awsErrorDetails().errorMessage()).build();
        }
    }

    @DELETE
    @Path("/delete")
    public Response deleteUser(@QueryParam("username") String Username, @HeaderParam("Auth") String idToken) {
        // Extract ID  token from the headers
        String userId;
        DecodedJWT decodedJWT = JWT.decode(idToken);

        try {
            userId = TokenVerifier.verifyToken(idToken, issuer);
        } catch (Exception e) {
            return Response.status(Response.Status.FORBIDDEN).entity("Invalid token.").build();
        }

        String username = decodedJWT.getClaim("cognito:username").asString();

        // Check if the username from the token matches the username from the path parameters
        if (!username.equals(Username)) {
            return Response.status(Response.Status.FORBIDDEN).entity("Not authorized to delete this user.").build();
        }

        // Perform user deletion logic
        try {
            AdminDeleteUserRequest deleteUserRequest = AdminDeleteUserRequest.builder()
                    .userPoolId(USER_POOL_ID)
                    .username(username)
                    .build();

            cognitoClient.adminDeleteUser(deleteUserRequest);

            return Response.ok("User deleted successfully").build();
        } catch (CognitoIdentityProviderException e) {
            if (e.statusCode() == 400 && e.awsErrorDetails().errorMessage().contains("User does not exist.")) {
                return Response.status(Response.Status.BAD_REQUEST).entity("Failed to delete user because it does not exist.").build();
            }
            return Response.status(Response.Status.INTERNAL_SERVER_ERROR).entity("Failed to delete user: " + e.awsErrorDetails().errorMessage()).build();
        }
    }
}
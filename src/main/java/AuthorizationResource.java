import com.google.gson.Gson;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.util.HashMap;
import java.util.Map;

@Path("/authorization")
public class AuthorizationResource {
    private static final String USER_POOL_ID = "us-east-1_cl8iVMzUw";
    private static final String CLIENT_APP_ID = "16fec44qrgoth26a20ob5ft0tb";
    private CognitoIdentityProviderClient cognitoClient = CognitoIdentityProviderClient.builder()
            .region(Region.US_EAST_1)
            .build();

    @POST
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
}
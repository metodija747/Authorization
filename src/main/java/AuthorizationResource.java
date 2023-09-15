import com.google.gson.Gson;
import com.kumuluz.ee.logs.cdi.Log;
import com.kumuluz.ee.logs.cdi.LogParams;
import io.opentracing.Span;
import io.opentracing.Tracer;
import org.eclipse.microprofile.faulttolerance.*;
import org.eclipse.microprofile.jwt.JsonWebToken;
import org.eclipse.microprofile.metrics.annotation.ConcurrentGauge;
import org.eclipse.microprofile.metrics.annotation.Counted;
import org.eclipse.microprofile.metrics.annotation.Metered;
import org.eclipse.microprofile.metrics.annotation.Timed;
import org.eclipse.microprofile.openapi.annotations.Operation;
import org.eclipse.microprofile.openapi.annotations.enums.ParameterIn;
import org.eclipse.microprofile.openapi.annotations.media.Content;
import org.eclipse.microprofile.openapi.annotations.media.Schema;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameter;
import org.eclipse.microprofile.openapi.annotations.parameters.Parameters;
import org.eclipse.microprofile.openapi.annotations.parameters.RequestBody;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponse;
import org.eclipse.microprofile.openapi.annotations.responses.APIResponses;
import org.eclipse.microprofile.openapi.annotations.security.SecurityRequirement;
import org.eclipse.microprofile.opentracing.Traced;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;
import software.amazon.awssdk.services.cognitoidentityprovider.model.NotAuthorizedException;

import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


@Path("/authorization")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@RequestScoped
@SecurityRequirement(name = "jwtAuth")
@Log(LogParams.METRICS)
public class AuthorizationResource {

    @Inject
    private Tracer tracer;

    @Inject
    private JsonWebToken jwt;

    @Inject
    private ConfigProperties configProperties;

    private volatile String currentRegion;
    private volatile String currentUserPoolId;
    private volatile String currentClientAppId;
    private volatile String currentIssuer;
    private volatile CognitoIdentityProviderClient cognitoClient;
    private static final Logger LOGGER = Logger.getLogger(AuthorizationResource.class.getName());

    private void checkAndUpdateCognitoClient() {
        String newRegion = configProperties.getDynamoRegion();
        String newUserPoolId = configProperties.getUserpoolId();
        String newClientAppId = configProperties.getClientappId();
        String newIssuer = configProperties.getCognitoIssuer();

        if (!newRegion.equals(currentRegion) || !newUserPoolId.equals(currentUserPoolId) || !newClientAppId.equals(currentClientAppId) || !newIssuer.equals(currentIssuer)) {
            try {
                this.cognitoClient = CognitoIdentityProviderClient.builder()
                        .region(Region.of(newRegion))
                        .build();
                currentRegion = newRegion;
                currentUserPoolId = newUserPoolId;
                currentClientAppId = newClientAppId;
                currentIssuer = newIssuer;
            } catch (Exception e) {
                Logger.getLogger(AuthorizationResource.class.getName()).severe("Error while creating Cognito client: " + e.getMessage());
                throw new WebApplicationException("Error while creating Cognito client: " + e.getMessage(), e, Response.Status.INTERNAL_SERVER_ERROR);
            }
        }
    }

    @POST
    @Operation(summary = "Register a new user",
            description = "This operation registers a new user in cognito.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "User registered successfully"),
            @APIResponse(responseCode = "403", description = "Forbidden. User already exists."),
            @APIResponse(responseCode = "500", description = "Internal Server Error")
    })
    @RequestBody(
            description = "User details required for registration",
            required = true,
            content = @Content(
                    schema = @Schema(
                            implementation = UserDetails.class,
                            example = "{ \"email\": \"john.doe@example.com\", \"password\": \"your-password\" }"
                    )
            )
    )
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Counted(name = "registerUserCount", description = "Count of registerUser calls")
    @Timed(name = "registerUserTime", description = "Time taken to register user")
    @Metered(name = "registerUserMetered", description = "Rate of registerUser calls")
    @ConcurrentGauge(name = "registerUserConcurrent", description = "Concurrent registerUser calls")
    @Timeout(value = 50, unit = ChronoUnit.SECONDS) // Timeout after 50 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "registerUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4, failureRatio = 0.5, delay = 2000)
    @Bulkhead(100) // Limit concurrent calls to 100
    @Traced
    public Response registerUser(UserDetails userDetails) {
        checkAndUpdateCognitoClient();
        Span span = tracer.buildSpan("registerUser").start();
        span.setTag("email", userDetails.getEmail());
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "registerUser");
        logMap.put("value", userDetails.getEmail());
        span.log(logMap);
        Logger.getLogger(AuthorizationResource.class.getName()).info("registerUser method called");

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
                    .clientId(currentClientAppId)
                    .username(email)
                    .password(password)
                    .userAttributes(emailAttribute) // adding the attributes
                    .build();

            SignUpResponse signUpResponse = cognitoClient.signUp(signUpRequest);

            // Immediately confirm the user
            AdminConfirmSignUpRequest confirmSignUpRequest = AdminConfirmSignUpRequest.builder()
                    .userPoolId(currentUserPoolId)
                    .username(email)
                    .build();

            cognitoClient.adminConfirmSignUp(confirmSignUpRequest);

            // Set email as verified
            AttributeType emailVerifiedAttribute = AttributeType.builder()
                    .name("email_verified")
                    .value("true") // setting email as verified
                    .build();

            AdminUpdateUserAttributesRequest updateUserAttributesRequest = AdminUpdateUserAttributesRequest.builder()
                    .userPoolId(currentUserPoolId)
                    .username(email)
                    .userAttributes(emailVerifiedAttribute)
                    .build();

            cognitoClient.adminUpdateUserAttributes(updateUserAttributesRequest);

            Logger.getLogger(AuthorizationResource.class.getName()).info("User successfully registered");
            span.setTag("completed", true);
            return Response.status(Response.Status.OK)
                    .entity(new Gson().toJson("User registered successfully"))
                    .build();
        } catch (UsernameExistsException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "User already exists", e);
            span.setTag("completed", false);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(new Gson().toJson("Forbidden. User already exists."))
                    .build();
        } catch (Exception e) {
            span.setTag("completed", false);
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Registration failed", e);
            throw new WebApplicationException("Registration failed", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }

    public Response registerUserFallback(UserDetails userDetails) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to register user at the moment for email: " + userDetails.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to register user at the moment. Please try again later.");
        return Response.status(500)
                .entity(new Gson().toJson(response))
                .build();
    }

    @POST
    @Operation(summary = "Login an existing user",
            description = "This operation logs an existing user into the system.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Successfully logged in"),
            @APIResponse(responseCode = "403", description = "Forbidden. Invalid credentials."),
            @APIResponse(responseCode = "500", description = "Internal Server Error")
    })
    @RequestBody(
            description = "User credentials required for login",
            required = true,
            content = @Content(
                    schema = @Schema(
                            implementation = UserDetails.class,
                            example = "{ \"email\": \"john.doe@example.com\", \"password\": \"your-password\" }"
                    )
            )
    )
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Counted(name = "loginUserCount", description = "Count of loginUser calls")
    @Timed(name = "loginUserTime", description = "Time taken to login user")
    @Metered(name = "loginUserMetered", description = "Rate of loginUser calls")
    @ConcurrentGauge(name = "loginUserConcurrent", description = "Concurrent loginUser calls")
    @Timeout(value = 50, unit = ChronoUnit.SECONDS) // Timeout after 50 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "loginUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4, failureRatio = 0.5, delay = 2000)
    @Bulkhead(100) // Limit concurrent calls to 100
    @Traced
    public Response loginUser(UserDetails userDetails) {
        checkAndUpdateCognitoClient();

        String username = userDetails.getEmail();
        String password = userDetails.getPassword();

        Map<String, String> authParams = new HashMap<>();
        authParams.put("USERNAME", username);
        authParams.put("PASSWORD", password);

        InitiateAuthRequest authRequest = InitiateAuthRequest.builder()
                .authFlow(AuthFlowType.USER_PASSWORD_AUTH)
                .clientId(currentClientAppId)
                .authParameters(authParams)
                .build();

        Span span = tracer.buildSpan("loginUser").start();
        span.setTag("username", username);
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "loginUser");
        logMap.put("value", username);
        span.log(logMap);
        Logger.getLogger(AuthorizationResource.class.getName()).info("LoginUser method called");

        try {
            InitiateAuthResponse authResponse = cognitoClient.initiateAuth(authRequest);
            // Check if the user is an admin
            AdminListGroupsForUserRequest listGroupsRequest = AdminListGroupsForUserRequest.builder()
                    .username(username)
                    .userPoolId(currentUserPoolId)
                    .build();

            AdminListGroupsForUserResponse listGroupsResponse = cognitoClient.adminListGroupsForUser(listGroupsRequest);

            boolean isAdmin = false;
            List<GroupType> groups = listGroupsResponse.groups();
            for (GroupType group : groups) {
                if (group.groupName().equals("Admins")) {
                    isAdmin = true;
                    break;
                }
            }
            // Create the response body
            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("accessToken", authResponse.authenticationResult().accessToken());
            responseBody.put("idToken", authResponse.authenticationResult().idToken());
            responseBody.put("RefreshToken", authResponse.authenticationResult().refreshToken());
            responseBody.put("isAdmin", isAdmin);

            span.setTag("completed", true);
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.INFO, "Successfully logged in");
            return Response.ok(responseBody).build();

        } catch (NotAuthorizedException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Forbidden. Invalid credentials.");
            span.setTag("error", true);
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(new Gson().toJson("Forbidden. Invalid credentials."))
                    .build();
        }catch (Exception e) {
            span.setTag("error", true);
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while signing in user " + username, e);
            throw new RuntimeException("Sign in failed", e);
        }
        finally {
            span.finish();
        }
    }
    public Response loginUserFallback(UserDetails userDetails) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to login at the moment for user: " + userDetails.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to login at the moment. Please try again later.");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(new Gson().toJson(response))
                .build();
    }

    private boolean userExists(String username) {
        try {
            AdminGetUserRequest getUserRequest = AdminGetUserRequest.builder()
                    .userPoolId(currentUserPoolId)
                    .username(username)
                    .build();
            cognitoClient.adminGetUser(getUserRequest);
            return true;
        } catch (UserNotFoundException e) {
            return false;
        }
    }

    @POST
    @Operation(summary = "Request a password reset",
            description = "This operation sends a password reset request to the email associated with the account.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Confirmation code sent to email"),
            @APIResponse(responseCode = "404", description = "User not found"),
            @APIResponse(responseCode = "500", description = "Internal Server Error")
    })
    @Parameters({
            @Parameter(
                    name = "email",
                    in = ParameterIn.QUERY,
                    description = "The email address associated with the account",
                    required = true,
                    example = "example@email.com"
            )
    })
    @Path("/forgot-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Counted(name = "forgotPasswordCount", description = "Count of forgotPassword calls")
    @Timed(name = "forgotPasswordTime", description = "Time taken to process forgot password request")
    @Metered(name = "forgotPasswordMetered", description = "Rate of forgotPassword calls")
    @ConcurrentGauge(name = "forgotPasswordConcurrent", description = "Concurrent forgotPassword calls")
    @Timeout(value = 20, unit = ChronoUnit.SECONDS) // Timeout after 20 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "forgotPasswordFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4, failureRatio = 0.5, delay = 2000)
    @Bulkhead(5) // Limit concurrent calls to 5
    @Traced
    public Response forgotPassword(@QueryParam("email") String Username) {
        checkAndUpdateCognitoClient();

        AdminGetUserRequest adminGetUserRequest = AdminGetUserRequest.builder()
                .userPoolId(currentUserPoolId)
                .username(Username)
                .build();

        Span span = tracer.buildSpan("forgotPassword").start();
        span.setTag("username", Username);
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "forgotPassword");
        logMap.put("value", Username);
        span.log(logMap);
        Logger.getLogger(AuthorizationResource.class.getName()).info("ForgotPassword method called");

        ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                .clientId(currentClientAppId)
                .username(Username)
                .build();
        try {
            if (!userExists(Username)) {
                span.setTag("error", true);
                Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "User with given email address does not exist.");
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("User with given email address does not exist.")
                        .build();
            }
            cognitoClient.forgotPassword(forgotPasswordRequest);
            LOGGER.info("Confirmation code sent successfully");
            span.setTag("completed", true);
            return Response.status(Response.Status.OK)
                    .entity("Confirmation code sent to your email!")
                    .build();


        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while processing forgot password for user " + Username, e);
            span.setTag("error", true);
            throw new WebApplicationException("ForgotPassword failed", e, Response.Status.INTERNAL_SERVER_ERROR);

        }finally {
            span.finish();
        }
    }
    public Response forgotPasswordFallback(@QueryParam("email") String Username) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to process forgot password at the moment for user: " + Username);
        Map<String, String> response = new HashMap<>();
        response.put("description","Unable to send confirmation code at the moment. Please try again later.");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(response)
                .build();
    }



    @POST
    @Operation(summary = "Confirm a password reset",
            description = "This operation confirms a password reset using a username, confirmation code, and new password.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "Password changed successfully"),
            @APIResponse(responseCode = "500", description = "Internal Server Error")
    })
    @RequestBody(
            description = "Details required for confirming the password reset",
            required = true,
            content = @Content(
                    schema = @Schema(
                            implementation = ConfirmPasswordDetails.class,
                            example = "{ \"email\": \"example@email.com\", \"confirmationCode\": \"255562\", \"newPassword\": \"Masters12345%\" }"
                    )
            )
    )
    @Path("/confirm-forgot-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Counted(name = "confirmForgotPasswordCount", description = "Count of confirmForgotPassword calls")
    @Timed(name = "confirmForgotPasswordTime", description = "Time taken to confirm forgot password")
    @Metered(name = "confirmForgotPasswordMetered", description = "Rate of confirmForgotPassword calls")
    @ConcurrentGauge(name = "confirmForgotPasswordConcurrent", description = "Concurrent confirmForgotPassword calls")
    @Timeout(value = 50, unit = ChronoUnit.SECONDS) // Timeout after 50 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "confirmForgotPasswordFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4, failureRatio = 0.5, delay = 2000)
    @Bulkhead(100) // Limit concurrent calls to 100
    @Traced
    public Response confirmForgotPassword(ConfirmPasswordDetails passwordDetails) {
        checkAndUpdateCognitoClient();

        String username = passwordDetails.getEmail();
        String confirmationCode = passwordDetails.getConfirmationCode();
        String newPassword = passwordDetails.getNewPassword();

        ConfirmForgotPasswordRequest confirmForgotPasswordRequest = ConfirmForgotPasswordRequest.builder()
                .clientId(currentClientAppId)
                .username(username)
                .confirmationCode(confirmationCode)
                .password(newPassword)
                .build();

        Span span = tracer.buildSpan("confirmForgotPassword").start();
        span.setTag("username", username);
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "confirmForgotPassword");
        logMap.put("value", username);
        span.log(logMap);
        Logger.getLogger(AuthorizationResource.class.getName()).info("confirmForgotPassword method called");

        try {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.INFO, "Password changed successfully");
            cognitoClient.confirmForgotPassword(confirmForgotPasswordRequest);
            span.setTag("completed", true);
            return Response.ok("Password changed successfully").build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while confirming forgot password for user " + username, e);
            span.setTag("error", true);
            throw new WebApplicationException("Error while confirming forgot password. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }
    public Response confirmForgotPasswordFallback(ConfirmPasswordDetails passwordDetails) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to change password at the moment for user: " + passwordDetails.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to change password at the moment. Please try again later.");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(response)
                .build();
    }

    @DELETE
    @Operation(summary = "Delete a user",
            description = "Deletes a user by the email address provided as a query parameter.")
    @APIResponses({
            @APIResponse(responseCode = "200", description = "User deleted successfully"),
            @APIResponse(responseCode = "401", description = "Unauthorized"),
            @APIResponse(responseCode = "500", description = "Internal Server Error")
    })
    @Parameters({
            @Parameter(
                    name = "email",
                    in = ParameterIn.QUERY,
                    description = "The email address associated with the account",
                    required = true,
                    example = "example@email.com"
            )
    })
    @Path("/delete")
    @Counted(name = "deleteUserCount", description = "Count of deleteUser calls")
    @Timed(name = "deleteUserTime", description = "Time taken to delete user")
    @Metered(name = "deleteUserMetered", description = "Rate of deleteUser calls")
    @ConcurrentGauge(name = "deleteUserConcurrent", description = "Concurrent deleteUser calls")
    @Timeout(value = 50, unit = ChronoUnit.SECONDS) // Timeout after 50 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "deleteUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4, failureRatio = 0.5, delay = 2000)
    @Bulkhead(100) // Limit concurrent calls to 100
    @Traced
    public Response deleteUser(@QueryParam("email") String Username) {
        checkAndUpdateCognitoClient();

        if (jwt == null) {
            LOGGER.log(Level.SEVERE, "Token verification failed");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Invalid token.")
                    .build();
        }
        if (!jwt.getClaim("email").equals(Username)) {
            LOGGER.log(Level.SEVERE, "Emails don't match");
            return Response.status(Response.Status.UNAUTHORIZED)
                    .entity("Unauthorized: you are not allowed to delete this email!")
                    .build();
        }
        Span span = tracer.buildSpan("deleteUser").start();
        span.setTag("username", Username);
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "deleteUser");
        logMap.put("value", Username);
        span.log(logMap);
        LOGGER.info("deleteUser method called");

        try {
            AdminDeleteUserRequest deleteUserRequest = AdminDeleteUserRequest.builder()
                    .userPoolId(currentUserPoolId)
                    .username(Username)
                    .build();
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.INFO, "User deleted successfully ");
            cognitoClient.adminDeleteUser(deleteUserRequest);
            span.setTag("completed", true);
            return Response.ok("User deleted successfully").build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while deleting user " + Username, e);
            span.setTag("error", true);
            if (e.statusCode() == 400 && e.awsErrorDetails().errorMessage().contains("User does not exist.")) {
                return Response.status(Response.Status.NOT_FOUND)
                        .entity("Failed to delete user because it does not exist.")
                        .build();
            }
            throw new WebApplicationException("Failed to delete user. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }
    public Response deleteUserFallback(@QueryParam("email") String Username) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to delete user at the moment for user: " + Username);
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to delete user at the moment. Please try again later.");
        return Response.status(Response.Status.INTERNAL_SERVER_ERROR)
                .entity(response)
                .build();
    }

}
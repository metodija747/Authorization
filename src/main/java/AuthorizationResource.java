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
import org.eclipse.microprofile.opentracing.Traced;
import software.amazon.awssdk.regions.Region;
import software.amazon.awssdk.services.cognitoidentityprovider.CognitoIdentityProviderClient;
import software.amazon.awssdk.services.cognitoidentityprovider.model.*;

import javax.annotation.security.PermitAll;
import javax.enterprise.context.RequestScoped;
import javax.inject.Inject;
import javax.ws.rs.*;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Level;
import java.util.logging.Logger;


@Path("/authorization")
@Consumes(MediaType.APPLICATION_JSON)
@Produces(MediaType.APPLICATION_JSON)
@RequestScoped
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
    @Path("/register")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Counted(name = "registerUserCount", description = "Count of registerUser calls")
    @Timed(name = "registerUserTime", description = "Time taken to register user")
    @Metered(name = "registerUserMetered", description = "Rate of registerUser calls")
    @ConcurrentGauge(name = "registerUserConcurrent", description = "Concurrent registerUser calls")
    @Timeout(value = 20, unit = ChronoUnit.SECONDS) // Timeout after 20 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "registerUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4) // Use circuit breaker after 4 failed requests
    @Bulkhead(5) // Limit concurrent calls to 5
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

            span.setTag("completed", true);
            return Response.ok("User registered successfully").build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while registering user " + email, e);
            span.setTag("error", true);
            throw new WebApplicationException("Failed to register user. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }

    public Response registerUserFallback(UserDetails userDetails) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to register user at the moment for email: " + userDetails.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to register user at the moment. Please try again later.");
        return Response.ok(response).build();
    }

    @POST
    @Path("/login")
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Counted(name = "loginUserCount", description = "Count of loginUser calls")
    @Timed(name = "loginUserTime", description = "Time taken to login user")
    @Metered(name = "loginUserMetered", description = "Rate of loginUser calls")
    @ConcurrentGauge(name = "loginUserConcurrent", description = "Concurrent loginUser calls")
    @Timeout(value = 20, unit = ChronoUnit.SECONDS) // Timeout after 20 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "loginUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4) // Use circuit breaker after 4 failed requests
    @Bulkhead(5) // Limit concurrent calls to 5
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

            Map<String, Object> responseBody = new HashMap<>();
            responseBody.put("accessToken", authResponse.authenticationResult().accessToken());
            responseBody.put("idToken", authResponse.authenticationResult().idToken());
            responseBody.put("RefreshToken", authResponse.authenticationResult().refreshToken());

            span.setTag("completed", true);
            return Response.ok(responseBody).build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while logging in user " + username, e);
            span.setTag("error", true);
            throw new WebApplicationException("Error while logging in. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }
    public Response loginUserFallback(UserDetails userDetails) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to login at the moment for user: " + userDetails.getEmail());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to login at the moment. Please try again later.");
        return Response.ok(response).build();
    }



    @POST
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
    @CircuitBreaker(requestVolumeThreshold = 4) // Use circuit breaker after 4 failed requests
    @Bulkhead(5) // Limit concurrent calls to 5
    @Traced
    public Response forgotPassword(@QueryParam("username") String Username) {
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

        try {
            cognitoClient.adminGetUser(adminGetUserRequest);
        } catch (UserNotFoundException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "User not found " + Username, e);
            span.setTag("error", true);
            throw new WebApplicationException("User with given email address does not exist.", e, Response.Status.NOT_FOUND);
        }

        ForgotPasswordRequest forgotPasswordRequest = ForgotPasswordRequest.builder()
                .clientId(currentClientAppId)
                .username(Username)
                .build();
        try {
            cognitoClient.forgotPassword(forgotPasswordRequest);
            span.setTag("completed", true);
            return Response.ok("Confirmation code sent to your email!").build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while processing forgot password for user " + Username, e);
            span.setTag("error", true);
            throw new WebApplicationException("Error while processing forgot password. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }
    public Response forgotPasswordFallback(@QueryParam("username") String Username) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to process forgot password at the moment for user: " + Username);
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to process forgot password at the moment. Please try again later.");
        return Response.ok(response).build();
    }


    @POST
    @Path("/confirm-forgot-password")
    @Produces(MediaType.APPLICATION_JSON)
    @Consumes(MediaType.APPLICATION_JSON)
    @Counted(name = "confirmForgotPasswordCount", description = "Count of confirmForgotPassword calls")
    @Timed(name = "confirmForgotPasswordTime", description = "Time taken to confirm forgot password")
    @Metered(name = "confirmForgotPasswordMetered", description = "Rate of confirmForgotPassword calls")
    @ConcurrentGauge(name = "confirmForgotPasswordConcurrent", description = "Concurrent confirmForgotPassword calls")
    @Timeout(value = 20, unit = ChronoUnit.SECONDS) // Timeout after 20 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "confirmForgotPasswordFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4) // Use circuit breaker after 4 failed requests
    @Bulkhead(5) // Limit concurrent calls to 5
    @Traced
    public Response confirmForgotPassword(ConfirmPasswordDetails passwordDetails) {
        checkAndUpdateCognitoClient();

        String username = passwordDetails.getUsername();
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
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to confirm forgot password at the moment for user: " + passwordDetails.getUsername());
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to confirm forgot password at the moment. Please try again later.");
        return Response.ok(response).build();
    }

    @DELETE
    @Path("/delete")
    @Counted(name = "deleteUserCount", description = "Count of deleteUser calls")
    @Timed(name = "deleteUserTime", description = "Time taken to delete user")
    @Metered(name = "deleteUserMetered", description = "Rate of deleteUser calls")
    @ConcurrentGauge(name = "deleteUserConcurrent", description = "Concurrent deleteUser calls")
    @Timeout(value = 20, unit = ChronoUnit.SECONDS) // Timeout after 20 seconds
    @Retry(maxRetries = 3) // Retry up to 3 times
    @Fallback(fallbackMethod = "deleteUserFallback") // Fallback method if all retries fail
    @CircuitBreaker(requestVolumeThreshold = 4) // Use circuit breaker after 4 failed requests
    @Bulkhead(5) // Limit concurrent calls to 5
    @Traced
    public Response deleteUser(@QueryParam("username") String Username) {
        checkAndUpdateCognitoClient();

        if (jwt == null) {
            LOGGER.info("Unauthorized: only authenticated users can delete their account.");
            return Response.ok("Unauthorized: only authenticated users can delete their account.").build();
        }
        Span span = tracer.buildSpan("deleteUser").start();
        span.setTag("username", Username);
        Map<String, Object> logMap = new HashMap<>();
        logMap.put("event", "deleteUser");
        logMap.put("value", Username);
        span.log(logMap);
        LOGGER.info("deleteUser method called");

        // Perform user deletion logic
        try {
            AdminDeleteUserRequest deleteUserRequest = AdminDeleteUserRequest.builder()
                    .userPoolId(currentUserPoolId)
                    .username(Username)
                    .build();

            cognitoClient.adminDeleteUser(deleteUserRequest);
            span.setTag("completed", true);
            return Response.ok("User deleted successfully").build();
        } catch (CognitoIdentityProviderException e) {
            Logger.getLogger(AuthorizationResource.class.getName()).log(Level.SEVERE, "Error while deleting user " + Username, e);
            span.setTag("error", true);
            if (e.statusCode() == 400 && e.awsErrorDetails().errorMessage().contains("User does not exist.")) {
                return Response.status(Response.Status.OK).entity("Failed to delete user because it does not exist.").build();
            }
            throw new WebApplicationException("Failed to delete user. Please try again later.", e, Response.Status.INTERNAL_SERVER_ERROR);
        } finally {
            span.finish();
        }
    }
    public Response deleteUserFallback(@QueryParam("username") String Username) {
        Logger.getLogger(AuthorizationResource.class.getName()).info("Fallback activated: Unable to delete user at the moment for user: " + Username);
        Map<String, String> response = new HashMap<>();
        response.put("description", "Unable to delete user at the moment. Please try again later.");
        return Response.ok(response).build();
    }

}
import com.kumuluz.ee.configuration.cdi.ConfigBundle;
import com.kumuluz.ee.configuration.cdi.ConfigValue;

import javax.enterprise.context.ApplicationScoped;

@ApplicationScoped
@ConfigBundle("aws-config")
public class ConfigProperties {

    @ConfigValue(value = "dynamo-region", watch = true)
    private String dynamoRegion;

    @ConfigValue(value = "userpool-id", watch = true)
    private String userpoolId;

    @ConfigValue(value = "clientapp-id", watch = true)
    private String clientappId;

    @ConfigValue(value = "cognito-issuer", watch = true)
    private String cognitoIssuer;

    // getter and setter methods

    public String getDynamoRegion() {
        return dynamoRegion;
    }

    public void setDynamoRegion(String dynamoRegion) {
        this.dynamoRegion = dynamoRegion;
    }

    public String getUserpoolId() {
        return userpoolId;
    }

    public void setUserpoolId(String userpoolId) {
        this.userpoolId = userpoolId;
    }

    public String getClientappId() {
        return clientappId;
    }

    public void setClientappId(String clientappId) {
        this.clientappId = clientappId;
    }

    public String getCognitoIssuer() {
        return cognitoIssuer;
    }

    public void setCognitoIssuer(String cognitoIssuer) {
        this.cognitoIssuer = cognitoIssuer;
    }
}

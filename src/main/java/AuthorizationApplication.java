import com.kumuluz.ee.discovery.annotations.RegisterService;
import javax.ws.rs.ApplicationPath;
import javax.ws.rs.core.Application;
import java.util.logging.Logger;

@ApplicationPath("/")
@RegisterService
public class AuthorizationApplication extends Application {
    private static final Logger LOG = Logger.getLogger(AuthorizationApplication.class.getName());
    public AuthorizationApplication() {
        LOG.info("AuthorizationApplication started!");
    }
}

package wendergalan.github.io.core.property;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.context.annotation.Configuration;

@Configuration
@ConfigurationProperties(prefix = "jwt.config")
@Data
public class JwtConfiguration {
    private String loginUrl = "/login/**";
    @NestedConfigurationProperty
    private Header header = new Header();
    private int expiration = 3600;
    private String privateKey = "jxbTbIEqdpfhDjDQXPl4KfGQSAuFmStq";
    private String type = "encrypted";

    @Data
    public static class Header {
        private String name = "Authorization";
        private String prefix = "Bearer ";
    }
}

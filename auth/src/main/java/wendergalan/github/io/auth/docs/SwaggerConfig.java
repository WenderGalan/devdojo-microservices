package wendergalan.github.io.auth.docs;

import org.springframework.context.annotation.Configuration;
import springfox.documentation.swagger2.annotations.EnableSwagger2;
import wendergalan.github.io.core.docs.BaseSwaggerConfig;

@Configuration
@EnableSwagger2
public class SwaggerConfig extends BaseSwaggerConfig {
    public SwaggerConfig() {
        super("wendergalan.github.io.auth.endpoint.controller");
    }
}

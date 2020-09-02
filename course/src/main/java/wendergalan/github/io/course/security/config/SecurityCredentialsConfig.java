package wendergalan.github.io.course.security.config;

import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter;
import wendergalan.github.io.core.property.JwtConfiguration;
import wendergalan.github.io.security.config.SecurityTokenConfig;
import wendergalan.github.io.security.filter.JwtTokenAuthotizationFilter;
import wendergalan.github.io.security.token.creator.converter.TokenConverter;

@EnableWebSecurity
public class SecurityCredentialsConfig extends SecurityTokenConfig {
    private final TokenConverter tokenConverter;

    public SecurityCredentialsConfig(JwtConfiguration jwtConfiguration,
                                     TokenConverter tokenConverter) {
        super(jwtConfiguration);
        this.tokenConverter = tokenConverter;

    }

    @Override
    protected void configure(HttpSecurity http) throws Exception {
        http.addFilterAfter(new JwtTokenAuthotizationFilter(jwtConfiguration, tokenConverter), UsernamePasswordAuthenticationFilter.class);
        super.configure(http);
    }
}

package wendergalan.github.io.course;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.boot.autoconfigure.domain.EntityScan;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.data.jpa.repository.config.EnableJpaRepositories;
import wendergalan.github.io.core.property.JwtConfiguration;

@SpringBootApplication
@EntityScan({"wendergalan.github.io.core.model"})
@EnableJpaRepositories({"wendergalan.github.io.core.repository"})
@EnableConfigurationProperties(value = JwtConfiguration.class)
@ComponentScan("wendergalan.github.io")
public class CourseApplication {

    public static void main(String[] args) {
        SpringApplication.run(CourseApplication.class, args);
    }

}

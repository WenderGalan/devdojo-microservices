package wendergalan.github.io.core.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.*;

import javax.persistence.Column;
import javax.persistence.Entity;
import javax.persistence.GeneratedValue;
import javax.persistence.Id;
import javax.validation.constraints.NotNull;

import static javax.persistence.GenerationType.IDENTITY;

@Entity
@Data
@Builder
@AllArgsConstructor
@NoArgsConstructor
@ToString
@EqualsAndHashCode(onlyExplicitlyIncluded = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class ApplicationUser implements AbstractEntity {

    @Id
    @GeneratedValue(strategy = IDENTITY)
    @EqualsAndHashCode.Include
    private Long id;

    @NotNull(message = "The field username is mandatory")
    @Column(nullable = false)
    private String username;

    @ToString.Exclude
    @NotNull(message = "The field password is mandatory")
    @Column(nullable = false)
    private String password;

    @NotNull(message = "The field role is mandatory")
    @Column(nullable = false)
    @Builder.Default
    private String role = "USER";

    public ApplicationUser(ApplicationUser applicationUser) {
        this.id = applicationUser.getId();
        this.username = applicationUser.getUsername();
        this.password = applicationUser.getPassword();
        this.role = applicationUser.getRole();
    }
}

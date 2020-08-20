package wendergalan.github.io.core.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import wendergalan.github.io.core.model.ApplicationUser;

public interface ApplicationUserRepository extends PagingAndSortingRepository<ApplicationUser, Long> {

    ApplicationUser findByUsername(String username);
}

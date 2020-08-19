package wendergalan.github.io.core.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import wendergalan.github.io.core.model.Course;

@Repository
public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {

}

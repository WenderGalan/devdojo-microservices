package wendergalan.github.io.core.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import wendergalan.github.io.core.model.Course;

public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {

}

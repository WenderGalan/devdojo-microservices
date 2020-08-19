package wendergalan.github.io.course.repository;

import org.springframework.data.repository.PagingAndSortingRepository;
import org.springframework.stereotype.Repository;
import wendergalan.github.io.course.model.Course;

@Repository
public interface CourseRepository extends PagingAndSortingRepository<Course, Long> {

}

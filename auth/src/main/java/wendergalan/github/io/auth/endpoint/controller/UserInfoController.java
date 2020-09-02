package wendergalan.github.io.auth.endpoint.controller;

import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import wendergalan.github.io.core.model.ApplicationUser;

import java.security.Principal;

import static org.springframework.http.HttpStatus.OK;

@RestController
@RequestMapping("user")
public class UserInfoController {

    @GetMapping(path = "info", produces = MediaType.APPLICATION_JSON_UTF8_VALUE)
    public ResponseEntity<ApplicationUser> getUserInfo(Principal principal) {
        ApplicationUser applicationUser = (ApplicationUser) ((UsernamePasswordAuthenticationToken) principal).getPrincipal();
        return new ResponseEntity<>(applicationUser, OK);
    }
}

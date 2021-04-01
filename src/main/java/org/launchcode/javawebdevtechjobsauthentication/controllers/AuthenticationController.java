package org.launchcode.javawebdevtechjobsauthentication.controllers;


import org.launchcode.javawebdevtechjobsauthentication.models.User;
import org.launchcode.javawebdevtechjobsauthentication.models.data.DTO.LoginFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.data.DTO.RegisterFormDTO;
import org.launchcode.javawebdevtechjobsauthentication.models.data.UserRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.validation.Errors;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.PostMapping;


import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpSession;
import javax.validation.Valid;
import java.util.Optional;

@Controller
public class AuthenticationController {

    @Autowired
    UserRepository userRepository;

    private static final String userSessionKey = "user";

    public User getUserFromSession(HttpSession session) {
        Integer userId = (Integer) session.getAttribute(userSessionKey);
        if (userId == null) {
            return null;
        }

        Optional<User> user = userRepository.findById(userId);

        if (user.isEmpty()) {
            return null;
        }

        return user.get();
    }

    private static void setUserInSession(HttpSession session, User user) {
        session.setAttribute(userSessionKey, user.getId());
    }

    //render the registration Form
    @GetMapping("/register")
    public String displayRegistrationForm(Model model) {
        model.addAttribute(new RegisterFormDTO());
        model.addAttribute("title", "Register");
        return "register";
    }

//    Define the handler method at the route /register that takes a valid RegisterFormDTO object,
//    associated errors, and a Model. In addition, the method needs an HttpServletRequest object.
//    This object represents the incoming request, and will be provided by Spring.

    @PostMapping("/register")
    public String processRegistrationForm(@ModelAttribute @Valid RegisterFormDTO registerFormDTO,
                                          Errors errors, HttpServletRequest request,
                                          Model model) {

//      Return the user to the form if an validation errors occur.
        if (errors.hasErrors()) {
            model.addAttribute("title", "Register");
            return "register";
        }
//      Retrieve the user with the given username from the database
        User existingUser = userRepository.findByUsername(registerFormDTO.getUsername());

//         If a user with the given username already exists,
//         register a custom error with the errors object and return the user to the form.
        if (existingUser != null) {
            errors.rejectValue("username", "username.alreadyexists", "A user with that username already exists");
            model.addAttribute("title", "Register");
            return "register";
        }

//        Compare the two passwords submitted. If they do not match, register a custom error and return the user to the form.
        String password = registerFormDTO.getPassword();
        String verifyPassword = registerFormDTO.getVerifyPassword();
        if (!password.equals(verifyPassword)) {
            errors.rejectValue("password", "passwords.mismatch", "Passwords do not match");
            model.addAttribute("title", "Register");
            return "register";
        }

//        At this point, we know that a user with the given username does NOT already exist,
//        and the rest of the form data is valid. So we create a new user object, store it in the database,
//        and then create a new session for the user.
        User newUser = new User(registerFormDTO.getUsername(), registerFormDTO.getPassword());
        userRepository.save(newUser);
        setUserInSession(request.getSession(), newUser);

//        redirect the user to the home page
        return "redirect:";
    }

//    render login info
    @GetMapping("/login")
    public String displayLoginForm(Model model) {
        model.addAttribute(new LoginFormDTO());
        model.addAttribute("title", "Log In");
        return "login";
    }

//    method definition, parameters, and initial error checking are nearly identical to the registration POST handler above.
    @PostMapping("/login")
    public String processLoginForm(@ModelAttribute @Valid LoginFormDTO loginFormDTO,
                                   Errors errors, HttpServletRequest request,
                                   Model model) {

        if (errors.hasErrors()) {
            model.addAttribute("title", "Log In");
            return "login";
        }

//        Retrieves the User object with the given password from the database.
        User theUser = userRepository.findByUsername(loginFormDTO.getUsername());

//        If no such user exists, register a custom error and return to the form.
        if (theUser == null) {
            errors.rejectValue("username", "user.invalid", "The given username does not exist");
            model.addAttribute("title", "Log In");
            return "login";
        }

//        Retrieves the submitted password from the form DTO.
        String password = loginFormDTO.getPassword();

//        If the password is incorrect, register a custom error and return to the form.
//        Password verification uses the User.isMatchingPassword() method,
//        which handles the details associated with checking hashed passwords.
        if (!theUser.isMatchingPassword(password)) {
            errors.rejectValue("password", "password.invalid", "Invalid password");
            model.addAttribute("title", "Log In");
            return "login";
        }

//        At this point, we know the given user exists and that the submitted password is correct.
//        So we create a new session for the user.
        setUserInSession(request.getSession(), theUser);

//        redirect the user to the home page
        return "redirect:";
    }


    @GetMapping("/logout")
    public String logout(HttpServletRequest request){
        request.getSession().invalidate();
        return "redirect:/login";
    }
}


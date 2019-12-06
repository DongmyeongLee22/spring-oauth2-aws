package me.sun.springoauth2aws;

import me.sun.springoauth2aws.config.dto.SessionUser;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

import javax.servlet.http.HttpSession;

@Controller
public class IndexController {

    @GetMapping("/")
    public String index(Model model,
                        HttpSession httpSession){

        SessionUser user = (SessionUser)httpSession.getAttribute("user");

        if (user != null){
            model.addAttribute("userName", user.getName());
        }

        return "index";
    }
}

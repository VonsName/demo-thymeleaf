package com.example.demothymeleaf;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;

/**
 * @author ASUS
 */
@Controller
public class SecurityController {
    private final String PREFIX="pages/";

    @GetMapping(value = "/")
    public String index(){
        return "welcome";
    }

    @GetMapping(value = "login")
    public String loginPage(){
        return PREFIX+"login";
    }

    @GetMapping(value = "/level1/{path}")
    public String level1(@PathVariable("path")String path){
        return PREFIX+"level1/"+path;
    }

    @GetMapping(value = "/level2/{path}")
    public String level2(@PathVariable("path")String path){
        return PREFIX+"level2/"+path;
    }

    @GetMapping(value = "/level3/{path}")
    public String level3(@PathVariable("path")String path){
        return PREFIX+"level3/"+path;
    }
}

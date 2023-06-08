package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController("/helllo")
public class ControllerApp {

  @GetMapping("/")
  String hello() {
    return "hello world.";
  }
}

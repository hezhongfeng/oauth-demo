package com.example.demo;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class ControllerApp {
  @GetMapping("/")
  String index() {
    return "hello";
  }
}

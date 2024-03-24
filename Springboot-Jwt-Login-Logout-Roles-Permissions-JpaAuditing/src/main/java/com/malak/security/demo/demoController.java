package com.malak.security.demo;

import io.swagger.v3.oas.annotations.Hidden;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/v1/demo-controller")

@SecurityRequirement(
        name = "bearerAuth" // to accept bearer token
)
@Tag(name = "Demo")
@Hidden
public class demoController {

    @Operation(
            description = "Tester token security",
            summary = "This is summary for demo Endpoint",
            responses = {
                    @ApiResponse(
                            description = "success",
                            responseCode = "200"
                    ),
                    @ApiResponse(
                            description = "Unauthorized",
                            responseCode = "403"
                    )
            }
    )
    @GetMapping
    public ResponseEntity<String> sayHello() {
        return ResponseEntity.ok("HEllo from  secured endpoint");
    }
}

package com.aesaibuddy.controller;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;
import com.aesaibuddy.service.VersionService;
import com.aesaibuddy.dto.VersionInfoDto;
import org.springframework.web.bind.annotation.CrossOrigin;
import org.springframework.http.ResponseEntity;


@RestController
@RequestMapping("/api")
@CrossOrigin(origins = "${cors.origins}")
public class VersionController {

    @Autowired
    private VersionService versionService;

   @GetMapping("/version")
public ResponseEntity<VersionInfoDto> getVersion() {
    VersionInfoDto VersionInfoDto = versionService.getVersion();
    return ResponseEntity.ok(VersionInfoDto); // Automatically sets Content-Type to application/json
}
}

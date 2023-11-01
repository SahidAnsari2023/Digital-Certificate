package com.finzly.demo.controller;

import java.io.IOException;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.multipart.MultipartFile;

import com.finzly.demo.service.CerService;

@RestController
@RequestMapping
public class CerController {
	@Autowired
	CerService cerService;
	
	@GetMapping("/check")
	public ResponseEntity<String> checkFileName(@RequestParam("file") MultipartFile file, String password) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
		return cerService.check(file, password);
	}

}

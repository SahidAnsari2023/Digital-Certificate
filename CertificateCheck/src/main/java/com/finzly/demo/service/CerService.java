package com.finzly.demo.service;

import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Date;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.web.multipart.MultipartFile;

@Service
public class CerService {

	private static final Logger log = LoggerFactory.getLogger(CerService.class);

	public ResponseEntity<String> check(MultipartFile file, String password) 
			throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {
		try (FileWriter f = new FileWriter("logs/reps.log")) {
			Date exp;
			String fileName = file.getOriginalFilename();
			String extension = fileName.substring(fileName.lastIndexOf(".")).toLowerCase();
			switch (extension) {
			case ".p12":
				exp = checkExpiryDate(file, password, "P12");
				if (exp.after(new Date())) {
					f.write("This is a Valid Certificate that has validity till " + exp);
				} else {
					f.write("This is not a Valid Certificate that has expired on " + exp);
				}

				break;
			case ".jks":
				exp = checkExpiryDate(file, password, "JKS");
				if (exp.after(new Date())) {
					f.write("This is a Valid Certificate that has validity till " + exp);
				} else {
					f.write("This is not a Valid Certificate that has expired on " + exp);
				}
				break;
			case ".crt":
				exp = checkExpiryDate(file);
				if (exp.after(new Date())) {
					f.write("This is a Valid Certificate that has validity till " + exp);
				} else {
					f.write("This is not a Valid Certificate that has expired on " + exp);
				}
				break;
			default:
				return ResponseEntity.status(HttpStatus.NOT_FOUND).body("No CRT / JKS / P12 file found");
			}
			return ResponseEntity.ok(""+exp);
		}
		catch (Exception e) {
			e.printStackTrace();
			throw e;
		}
		
	}

	public Date checkExpiryDate(MultipartFile file) throws CertificateException, IOException {
		CertificateFactory fac = CertificateFactory.getInstance("X509");
		InputStream is = file.getInputStream();
		X509Certificate x509Certificate = (X509Certificate) fac.generateCertificate(is);
		log.info(x509Certificate.toString());
		return x509Certificate.getNotAfter();
	}

	public Date checkExpiryDate(MultipartFile file, String password, String type)
			throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
		try {
			InputStream is = file.getInputStream();
			KeyStore keystore = (type.equals("JKS")) ? (KeyStore.getInstance("JKS")) : (KeyStore.getInstance("PKCS12"));

			keystore.load(is, password.toCharArray());
			String alias = keystore.aliases().nextElement();
			Certificate certificate = keystore.getCertificate(alias);

			X509Certificate x509Certificate = (X509Certificate) certificate;
			log.info(x509Certificate.getNotAfter().toString());
			is.close();
			return x509Certificate.getNotAfter();
		} catch (IOException | CertificateException | KeyStoreException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			throw e;
		}
	}
}

package com.hashfile;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;

import java.io.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.util.Date;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class SignFile {

    private static PrivateKey getPrivateKey(String privKey, boolean fromString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (!fromString) {
            byte[] keyBytes = Files.readAllBytes(Paths.get(privKey));
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePrivate(spec);
        } else {
            String privateKB64 = new String(Files.readAllBytes(Paths.get(privKey)));
            String privateKeyPEM = privateKB64
                    .replaceAll("\\-*BEGIN.*KEY\\-*", "")
                    .replaceAll("\\-*END.*KEY\\-*", "")
                    .replaceAll("\r", "").replaceAll("\n", "");
            PKCS8EncodedKeySpec pubKeySpec = new PKCS8EncodedKeySpec(Base64.getDecoder().decode(privateKeyPEM));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePrivate(pubKeySpec);
        }
    }

    private static PublicKey getPublicKey(String pubKey, boolean fromString) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        if (!fromString) {
            byte[] keyBytes = Files.readAllBytes(Paths.get(pubKey));
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            return kf.generatePublic(spec);
        } else {
            String publicKB64 = new String(Files.readAllBytes(Paths.get(pubKey)));
            String publicPEM = publicKB64
                    .replaceAll("\\-*BEGIN.*KEY\\-*", "")
                    .replaceAll("\\-*END.*KEY\\-*", "")
                    .replaceAll("\r", "").replaceAll("\n", "");
            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicPEM));
            KeyFactory factory = KeyFactory.getInstance("RSA");
            return factory.generatePublic(pubKeySpec);
        }
    }

    public static void signFile(String fileName, String privKey, boolean fromString)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException,
            IOException, CertificateException, InvalidKeyException, IllegalBlockSizeException,
            BadPaddingException, SignatureException, InvalidKeySpecException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey(privKey, fromString));
        FileInputStream fis = new FileInputStream(fileName);
        byte[] buffer = new byte[1024];
        int numRead;
        do {
            numRead = fis.read(buffer);
            if (numRead > 0) {
                signature.update(buffer, 0, numRead);
            }
        } while (numRead != -1);
        fis.close();
        byte[] digitalSignature = signature.sign();
        /*String desktopPath = System.getProperty("user.home") + File.separator;
        String filepath = desktopPath + "TEST_HASH_SIGN.sign";*/
        String filepath = fileName.replaceAll("(?i)\\.txt$", ".sign");
        try (FileOutputStream fos = new FileOutputStream(filepath)) {
            fos.write(digitalSignature);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void signFileGz(String fileName, String privKey, boolean fromString)
            throws UnrecoverableKeyException, KeyStoreException, NoSuchAlgorithmException, IOException,
            CertificateException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, SignatureException, InvalidKeySpecException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(getPrivateKey(privKey, fromString));
        GZIPInputStream fis = new GZIPInputStream(new FileInputStream(fileName));
        byte[] buffer = new byte[1024];
        int numRead;
        long t1 = new Date().getTime();
        /*String desktopPath = System.getProperty("user.home") + File.separator;
        String filepath = desktopPath + "TEST_HASH_SIGN.sign.gz";*/
        String filepath = fileName.replaceAll("(?i)\\.txt$", ".sign");
        try (FileOutputStream fos = new FileOutputStream(filepath);
             GZIPOutputStream gos = new GZIPOutputStream(fos)) {
            do {
                numRead = ((GZIPInputStream) fis).read(buffer);
                if (numRead > 0) {
                    signature.update(buffer, 0, numRead);
                    gos.write(buffer, 0, numRead);
                }
            } while (numRead != -1);
        } catch (IOException e) {
            e.printStackTrace();
        } finally {
            fis.close();
        }
    }

    public static boolean verifySignature(String fileName, String pubKey, boolean fromString)
            throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException,
            CertificateException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(getPublicKey(pubKey, fromString));
        /*String desktopPath = System.getProperty("user.home") + File.separator;
        String filepath = desktopPath + "TEST_HASH_SIGN.sign";*/
        String filepath = fileName.replaceAll("(?i)\\.txt$", ".sign");
        byte[] receivedSignature = Files.readAllBytes(Paths.get(filepath));
        FileInputStream fis = new FileInputStream(fileName);
        byte[] buffer = new byte[1024];
        int numRead;
        do {
            numRead = ((FileInputStream) fis).read(buffer);
            if (numRead > 0) {
                signature.update(buffer, 0, numRead);
            }
        } while (numRead != -1);
        fis.close();
        return signature.verify(receivedSignature);
    }

    public static boolean verifySignatureGz(String fileName, String pubKey, boolean fromString)
            throws KeyStoreException, IOException, UnrecoverableKeyException, NoSuchAlgorithmException,
            CertificateException, InvalidKeyException, SignatureException, InvalidKeySpecException {
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initVerify(getPublicKey(pubKey, fromString));
        /*String desktopPath = System.getProperty("user.home") + File.separator;
        String filepath = desktopPath + "TEST_HASH_SIGN.sign.gz";*/
        String filepath = fileName.replaceAll("(?i)\\.txt$", ".sign");
        byte[] receivedSignature = Files.readAllBytes(Paths.get(filepath));
        GZIPInputStream fis = new GZIPInputStream(new FileInputStream(fileName));
        byte[] buffer = new byte[1024];
        int numRead;
        do {
            numRead = ((GZIPInputStream) fis).read(buffer);
            if (numRead > 0) {
                signature.update(buffer, 0, numRead);
            }
        } while (numRead != -1);
        fis.close();
        return signature.verify(receivedSignature);
    }
}

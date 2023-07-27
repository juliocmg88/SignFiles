package com.hashfile;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class TestSignFile {

    public static void main(String[] args) {
    	if(args.length > 0) {
    		// Firma y verificación fichero sin comprimir
            /*String desktopPath = System.getProperty("user.home") + File.separator;
            String fileName = desktopPath + "TEST_HASH_SIGN.txt";
            String filePriv = desktopPath + "TEST_HASH_SIGN_PRIV.pem";
            String filePubl = desktopPath + "TEST_HASH_SIGN_PUBL.pem";*/
    		
    		String fileName = args[0]; 
    		String filePriv = fileName + "_privkey.pem";
    		String filePubl = fileName + "_pubkey.pem";

            try {
                // Generar el par de claves público/privado (solo hacerlo una vez)
                KeyPair keyPair = generateKeyPair(filePriv, filePubl);

                // Firmar el archivo usando la clave privada
                SignFile.signFile(fileName, filePriv, true);

                // Verificar la firma usando la clave pública
                boolean verify = SignFile.verifySignature(fileName, filePubl, true);
                System.out.println("Verificación de firma: " + verify);
            } catch (Exception e) {
                e.printStackTrace();
            }
    	} else {
            System.err.println("Se debe proporcionar el nombre del archivo a firmar como argumento.");
            System.exit(1);
    	}
        
    }

    private static KeyPair generateKeyPair(String privateKeyFilePath, String publicKeyFilePath) throws NoSuchAlgorithmException, IOException {
        // Verificar si las claves ya existen para no sobreescribirlas
        File privateKeyFile = new File(privateKeyFilePath);
        File publicKeyFile = new File(publicKeyFilePath);
        if (privateKeyFile.exists() && publicKeyFile.exists()) {
            System.out.println("Las claves ya existen en: " + privateKeyFilePath + " y " + publicKeyFilePath);
            System.out.println("No se generarán nuevas claves.");
        } else {
            // Obtener una instancia del generador de claves RSA
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");

            // Inicializar el generador con el tamaño de la clave (en este caso, 2048 bits)
            keyPairGenerator.initialize(2048);

            // Generar el par de claves público/privado
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            // Obtener la clave privada generada
            PrivateKey privateKey = keyPair.getPrivate();

            // Obtener la clave pública generada
            PublicKey publicKey = keyPair.getPublic();

            // Guardar las claves en archivos
            writeKeyToFile(privateKey, privateKeyFilePath);
            writeKeyToFile(publicKey, publicKeyFilePath);

            System.out.println("Par de claves público/privado generado con éxito en: " + privateKeyFilePath + " y " + publicKeyFilePath);
        }

        // Cargar y devolver el par de claves
        try {
			return loadKeyPair(privateKeyFilePath, publicKeyFilePath);
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
			return null;
		}
    }

    private static void writeKeyToFile(Key key, String filePath) throws IOException {
        byte[] keyBytes = key.getEncoded();
        String keyBase64 = java.util.Base64.getEncoder().encodeToString(keyBytes);

        try (FileWriter fileWriter = new FileWriter(filePath)) {
            fileWriter.write(keyBase64);
        }
    }

    private static KeyPair loadKeyPair(String privateKeyFilePath, String publicKeyFilePath) throws IOException, NoSuchAlgorithmException, InvalidKeySpecException {
        String privateKeyBase64 = new String(java.nio.file.Files.readAllBytes(new File(privateKeyFilePath).toPath()));
        String publicKeyBase64 = new String(java.nio.file.Files.readAllBytes(new File(publicKeyFilePath).toPath()));

        byte[] privateKeyBytes = java.util.Base64.getDecoder().decode(privateKeyBase64);
        byte[] publicKeyBytes = java.util.Base64.getDecoder().decode(publicKeyBase64);

        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(privateKeyBytes));
        PublicKey publicKey = keyFactory.generatePublic(new X509EncodedKeySpec(publicKeyBytes));

        return new KeyPair(publicKey, privateKey);
    }
}

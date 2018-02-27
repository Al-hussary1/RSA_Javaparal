/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package Javaapplication3;

/**
 *
 * @author GBADAMOSI ABDUSSAMAD
 */
import java.nio.file.Files;
import java.nio.file.Paths;
import java.io.FileWriter;
import java.io.InputStream;
import java.io.OutputStream;
import java.lang.Thread.State;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.*;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

/**
 *
 * @author GBADAMOSI ABDUSSAMAD
 */
public class JavaApplication3 {

    /**
     * @param args the command line arguments
     */
   private static final String PUBLIC_KEY_FILE = "Public.key";
   private static final String PRIVATE_KEY_FILE = "Private.key";
    
    /**
     *
     * @param args
     * @throws IOException
     */
    public static void main(String[] args)throws IOException{
        try{
            System.out.println("--------GENERATING PUBLIC AND PRIVATE KEY-------------");
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();
       
        PublicKey pub = kp.getPublic();
        PrivateKey priv = kp.getPrivate();
        System.out.println("Public Key: " + pub);
        System.out.println("Private Key: " + priv);
        
        //PARAMETERS THAT MAKE UP THE KEYS
        System.out.println("\n--------------PULLING OUT PARAMETRS THAT MAKE UP THE KEY PAIRS");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        RSAPublicKeySpec rsaPubKeySpec = kf.getKeySpec(pub, RSAPublicKeySpec.class);
        RSAPrivateKeySpec rsaPrivKeySpec = kf.getKeySpec(priv, RSAPrivateKeySpec.class);
        System.out.println("PubKey Modulus : " + rsaPubKeySpec.getModulus());
        System.out.println("PubKey Exponent : " + rsaPubKeySpec.getPublicExponent());
        System.out.println("PrivKey Modulus : " + rsaPrivKeySpec.getModulus());
        System.out.println("PrivKey Exponent : " + rsaPrivKeySpec.getPrivateExponent());
               
        System.out.println("\n--------SAVING PUBLIC KEY AND PRIVATE KEY TO FILE-----------");
        JavaApplication3 javApp3 = new JavaApplication3();
        javApp3.saveKeys(PUBLIC_KEY_FILE, rsaPubKeySpec.getModulus(), rsaPubKeySpec.getPublicExponent());
        javApp3.saveKeys(PRIVATE_KEY_FILE, rsaPrivKeySpec.getModulus(), rsaPrivKeySpec.getPrivateExponent());
        
        
        //Encrypt data using public key
        byte[] encryptedData = javApp3.encryptData();
        
        // Decrypt data using private key
        javApp3.decryptData(encryptedData);
       
        
        }catch(NoSuchAlgorithmException | InvalidKeySpecException ex){
        }
    }
    
        private void saveKeys(String fileName, BigInteger mod, BigInteger exp) throws IOException{
            FileOutputStream  fos = null;
            ObjectOutputStream oos = null;
            try{
                System.out.println("Generating " +fileName +"....");
                fos = new FileOutputStream(fileName);
                oos = new ObjectOutputStream(new BufferedOutputStream(fos));
                
                oos.writeObject(mod);
                oos.writeObject(exp);
                
                System.out.println(fileName + " generated successfully");
            }catch(IOException e){
            }finally{
                if(oos != null){
                    oos.close();
                    
                if(fos != null){
                    fos.close();
            }
         }
     }
}
        //

    /**
     *
     * @return
     * @throws IOException
     */
   public static String data()throws IOException{
      String fileBase = "C:\\Users\\GBADAMOSI ABDUSSAMAD\\Documents\\prac.txt";    
              byte [] buffer = new byte[1000];
      try{
          FileInputStream inputStream = new FileInputStream(fileBase);
              int total = 0;
              int nRead = 0;
              while((nRead = inputStream.read(buffer))!= -1){
                  System.out.println(new String(buffer));
                  total += nRead;
                  //System.out.println("Read " + total + " bytes");
                  inputStream.close();

                 return fileBase;
              
          }
      }catch(IOException ex){
      }
       return null;
    
   }
   
private byte[] encryptData() throws IOException{
    System.out.println("\n---------Encryption Started-----------\n");
    byte [] dataToEncrypt =  data().getBytes();
    byte [] encryptedData = null;
    try{
        PublicKey pubKey = readPublicKeyFromFile(PUBLIC_KEY_FILE);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        encryptedData = cipher.doFinal(dataToEncrypt);
        System.out.println("\nEncrypted Data: " + encryptedData);
    }catch(IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
    }
    System.out.println("---------ENCRYPTED COMPLETED------------");
    return encryptedData;
    }

private void decryptData(byte [] value) throws IOException{
    System.out.println("\n---------DECRYPTION STARTED-------------");
    byte [] decryptedData = null;
    try{
        PrivateKey privateKey = readPrivateKeyFromFile(PRIVATE_KEY_FILE);
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        decryptedData = cipher.doFinal(value);
        System.out.println("Decrypted Data: " +  new String(decryptedData));
        
    }catch(IOException | InvalidKeyException | NoSuchAlgorithmException | BadPaddingException | IllegalBlockSizeException | NoSuchPaddingException e){
    }
    System.out.println("-----------Decryption completed----------------");
}

    /**
     *
     * @param fileName
     * @return
     * @throws IOException
     */
    public PublicKey readPublicKeyFromFile(String fileName) throws IOException{
    FileInputStream fis = null;
    ObjectInputStream ois = null;
    try{
        fis = new FileInputStream(new File(fileName));
        ois = new ObjectInputStream(fis);
        
        BigInteger modulus = (BigInteger)ois.readObject();
        BigInteger exponent = (BigInteger)ois.readObject();
        
        //Get Public Key
        RSAPublicKeySpec rsaPublicKeySpec = new RSAPublicKeySpec(modulus, exponent);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PublicKey publicKey = fact.generatePublic(rsaPublicKeySpec);
        return publicKey;
        
    }catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
    }finally{
        if(ois != null){
            ois.close();
        if(fis != null){
            fis.close();
        }
        }
    }
    return null;
}

    /**
     *
     * @param fileName
     * @return
     * @throws IOException
     */
    public PrivateKey readPrivateKeyFromFile(String fileName) throws IOException{
    FileInputStream fis = null;
    ObjectInputStream ois = null;
    try{
        fis = new FileInputStream(new File(fileName));
        ois = new ObjectInputStream(fis);
        
        BigInteger modulus = (BigInteger)ois.readObject();
        BigInteger exponent = (BigInteger)ois.readObject();
        
        //Get Public Key
        RSAPrivateKeySpec rsaPrivateKeySpec = new RSAPrivateKeySpec(modulus, exponent);
        KeyFactory fact = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = fact.generatePrivate(rsaPrivateKeySpec);
        return privateKey;
        
    }catch(IOException | ClassNotFoundException | NoSuchAlgorithmException | InvalidKeySpecException e){
    }finally{
        if(ois != null){
            ois.close();
        if(fis != null){
            fis.close();
        }
        }
    }
    return null;
}

 

        

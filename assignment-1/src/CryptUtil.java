
import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.annotation.processing.SupportedSourceVersion;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.sound.midi.SysexMessage;
import javax.xml.transform.stream.StreamSource;


public class CryptUtil {

    public static byte[] createSha1(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-1");
        InputStream fis = new FileInputStream(file);
        int n = 0;
        byte[] buffer = new byte[8192];
        while (n != -1) {
            n = fis.read(buffer);
            if (n > 0) {
                digest.update(buffer, 0, n);
            }
        }
        fis.close();
        return digest.digest();
    }

    public static boolean compareSha1(String filename1, String filename2) throws Exception {
        File file1 = new File(filename1);
        File file2 = new File(filename2);
        byte[] fsha1 = CryptUtil.createSha1(file1);
        byte[] fsha2 = CryptUtil.createSha1(file2);
        return Arrays.equals(fsha1, fsha2);
    }

    public static double getShannonEntropy(String s) {
        int n = 0;
        Map<Character, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < s.length(); ++c_) {
            char cx = s.charAt(c_);
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Character, Integer> entry : occ.entrySet()) {
            char cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getShannonEntropy(byte[] data) {

        if (data == null || data.length == 0) {
            return 0.0;
        }

        int n = 0;
        Map<Byte, Integer> occ = new HashMap<>();

        for (int c_ = 0; c_ < data.length; ++c_) {
            byte cx = data[c_];
            if (occ.containsKey(cx)) {
                occ.put(cx, occ.get(cx) + 1);
            } else {
                occ.put(cx, 1);
            }
            ++n;
        }

        double e = 0.0;
        for (Map.Entry<Byte, Integer> entry : occ.entrySet()) {
            byte cx = entry.getKey();
            double p = (double) entry.getValue() / n;
            e += p * log2(p);
        }
        return -e;
    }

    public static double getFileShannonEntropy(String filePath) {
        try {
            byte[] content;
            content = Files.readAllBytes(Paths.get(filePath));
            return CryptUtil.getShannonEntropy(content);
        } catch (IOException e) {
            e.printStackTrace();
            return -1;
        }

    }

    private static double log2(double a) {
        return Math.log(a) / Math.log(2);
    }

    public static void doCopy(InputStream is, OutputStream os) throws IOException {
        byte[] bytes = new byte[64];
        int numBytes;
        while ((numBytes = is.read(bytes)) != -1) {
            os.write(bytes, 0, numBytes);
        }
        os.flush();
        os.close();
        is.close();
    }

    public static Byte randomKey() {
        int leftLimit = 48; // numeral '0'
        int rightLimit = 122; // letter 'z'
        int targetStringLength = 8;
        Random random = new Random();
        String generatedString = random.ints(leftLimit, rightLimit + 1)
                .filter(i -> (i <= 57 || i >= 65) && (i <= 90 || i >= 97))
                .limit(targetStringLength)
                .collect(StringBuilder::new, StringBuilder::appendCodePoint, StringBuilder::append)
                .toString();
        //System.out.println("RANDOOM: " + generatedString.getBytes()[0]);
        return generatedString.getBytes()[0];
    }

    /**
     * Encryption (Bytes)
     *
     * @param data : the data in bytes
     * @param key : the key in bytes
     * @return encrypted bytes
     */
    static int[][] sequence = {
            {3, 4, 2, 0, 6, 7, 1, 5},
            {7,5,6,2,3,0,1,4},
            {7,0,4,2,1,3,5,6},
            {2,0,1,5,4,3,7,6},
            {0,4,6,1,7,5,2,3},
            {1,7,0,3,4,2,5,6},
            {2,7,7,6,1,5,3,0},
            {7,2,3,1,1,5,3,4}
    };
    public static byte[] premutation(byte[] data , int p) {
        byte[] returnData = new byte[8];
        for(int i = 0; i < 8; i++){
            returnData[i] = data[sequence[p][i]];
        }
        return returnData;
    }
    public static Byte keyPermutation(Byte key) {

        String data3 = String.format("%8s",Integer.toBinaryString(key &  0xFF)).replace(" ", "0");

        String data2 = "";

        for(int i = 0; i < 8; i++){
            data2= data2 + data3.charAt(sequence[4][i]);
        }

        int asAInt = Integer.parseInt(data2,2);
        String dataAsInt = Integer.toString(asAInt+256);
        //System.out.println("KEY: " + key + "AFTER: " + dataAsInt);
        return data2.getBytes()[0];
    }
    public static byte[] unpremutation(byte[] data) {
        byte[] returnData = new byte[8];
        for(int i = 0; i < 8; i++){
            returnData[sequence[0][i]] = data[i];
        }
        return returnData;
    }
    public static Byte unkeyPermutation(Byte key) {
        String data = "00" + Integer.toBinaryString((int) key);

        String data2 = "";
        char[] returnData = new char[8];
        for(int i = 0; i < 8; i++){
            returnData[sequence[0][i]] = data.charAt(i);
        }
        for(int i = 0; i < 8; i++){
            data2 += returnData[i];
        }

        return data2.getBytes()[0];
    }

   /* public static byte[] cs4440Encrypt(byte[] data, Byte key) {
        // TODO
	byte[] cipherdata = new byte[data.length];
    Byte current = keyPermutation(key);
    data = premutation(data);

    for(int i = 0; i < data.length; i++){
        current = (byte) (data[i] ^ current);
        cipherdata[i] = current;
    }

	return cipherdata;
    }*/
   public static byte[] cs4440Encrypt(byte[] data, Byte key) {
       byte[] ciphertext = new byte[8];
       String data2 = "423";
       String data4 = "23d23";
       //System.out.println("BEFORE:" + key);
       key = keyPermutation(key);
       //System.out.println("AFTER: " + key);

       //data = premutation(data , 0);
       byte initializationVector = keyPermutation(data2.getBytes()[0]);
       for(int i = 0; i < 8; i++){
           if(i == 0){
               ciphertext[i] = (byte) ((initializationVector ^ ((key*key*key*key))) ^ data[i]);
           }
           else{
               ciphertext[i] = (byte) ((ciphertext[i-1] ^ ((key*key*key*key)))^ data[i]);
           }
       }

       return ciphertext;
   }

    /**
     * Encryption (file)
     *
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int encryptDoc(String plainfilepath, String cipherfilepath, Byte key) {
        try {
            BufferedReader br = new BufferedReader(new FileReader(plainfilepath));
            StringBuilder sb = new StringBuilder();
            String line = br.readLine();

            while (line != null) {
                sb.append(line);
                sb.append(System.lineSeparator());
                line = br.readLine();
            }
            String everything = sb.toString();
            br.close();

            PrintWriter writer = new PrintWriter(cipherfilepath, "UTF-8");

            String everything2 = "";
            int currentPlaceInString = 0;
            while(currentPlaceInString < everything.length()){
                byte[] toEncrypt = new byte[8];
                for(int j = 0; j < 8; j++){
                    String test = "";
                    test += everything.charAt(currentPlaceInString);
                    toEncrypt [j] = test.getBytes()[0];
                    currentPlaceInString++;
                }
                //for(int q = 0; q < 2; q++) {
                    for (int p = 0; p < 7; p++) {
                        toEncrypt = premutation(toEncrypt, p);
                        toEncrypt = cs4440Encrypt(toEncrypt, key);

                    }
                //}
                for(int i = 0; i < 8; i++){
                    writer.print((char)toEncrypt[i]);
                }
            }

            return 0;

        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * decryption
     *
     * @param data
     * @param key
     * @return decrypted content
     */

    public static byte[] cs4440Decrypt(byte[] data, Byte key) {
        byte[] plaintext = new byte[8];
        String data2 = "423";
        key = keyPermutation(key);

        byte initializationVector = keyPermutation(data2.getBytes()[0]);
        for(int i = 0; i < 8; i++){
            if(i == 0){
                plaintext[i] = (byte) (  (data[i]) ^ (initializationVector ^ (key*key*key*key)));
            }
            else{
                plaintext[i] = (byte) ( (data[i]) ^ (data[i-1] ^ (key*key*key*key)));
            }
        }
        return plaintext;
    }

   /* public static byte[] cs4440Decrypt(byte[] data, Byte key) {
        // TODO
        byte[] cipherdata = new byte[data.length];
        Byte current = key;
        current = unkeyPermutation(key);
        byte[] cipherdata = new byte[data.length];
        byte initializationVector = data2.getBytes()[0];
        //data = premutation(data);
        for(int i = 0; i < data.length; i++){
            cipherdata[i] = (byte) (data[i] ^ current);
            current = data[i];
        }
        cipherdata = unpremutation(cipherdata);


	//Your code here

	return cipherdata;

        //return 0;
    }*/

    /**
     * Decryption (file)
     * @param plainfilepath
     * @param cipherfilepath
     * @param key
     */
    public static int decryptDoc(String cipherfilepath, String plainfilepath, Byte key) {
        // TODO
        return 0;
    }

    public static void main(String[] args) {

        String targetFilepath = "";
        String encFilepath = "";
        String decFilepath = "";
        System.out.println(args[0].toString());
        if (args.length == 3) {
            try {
                File file1 = new File(args[0].toString());
                if (file1.exists() && !file1.isDirectory()) {
                    targetFilepath = args[0].toString();
                    System.out.println("success");
                } else {
                    System.out.println("File does not exist!");
                    System.exit(1);
                }

                encFilepath = args[1].toString();
                decFilepath = args[2].toString();
            } catch (Exception e) {
                e.printStackTrace();
                System.exit(1);
            }
        } else {
            // targetFilepath = "cs4440-a1-testcase1.html";
            System.out.println("Usage: java CryptoUtil file_to_be_encrypted encrypted_file decrypted_file");
            System.exit(1);
        }

        Byte key = randomKey();
        String src = "ABCDEFGH";
        System.out.println("[*] Now testing plain sample： " + src);
        try {
            byte[] encrypted = CryptUtil.cs4440Encrypt(src.getBytes(), key);
            StringBuilder encsb = new StringBuilder();
            for (byte b : encrypted) {
                encsb.append(String.format("%02X ", b));
            }
            System.out.println("[*] The  encrypted sample  [Byte Format]： " + encsb);
            double entropyStr = CryptUtil.getShannonEntropy(encrypted.toString());
            System.out.printf("[*] Shannon entropy of the text sample (to String): %.12f%n", entropyStr);
            double entropyBytes = CryptUtil.getShannonEntropy(encrypted);
            System.out.printf("[*] Shannon entropy of encrypted message (Bytes): %.12f%n", entropyBytes);

            byte[] decrypted = CryptUtil.cs4440Decrypt(encrypted, key);
	    if (Arrays.equals(decrypted, src.getBytes())){
                System.out.println("[+] It works!  decrypted ： " + decrypted);
            } else {
                System.out.println("Decrypted message does not match!");
            }

            // File Encryption
            System.out.printf("[*] Encrypting target file: %s \n", targetFilepath);
            System.out.printf("[*] The encrypted file will be: %s \n", encFilepath);
            System.out.printf("[*] The decrypted file will be: %s \n", decFilepath);

            CryptUtil.encryptDoc(targetFilepath, encFilepath, key);
            CryptUtil.decryptDoc(encFilepath, decFilepath, key);

            System.out.printf("[+] [File] Entropy of the original file: %s \n",
                    CryptUtil.getFileShannonEntropy(targetFilepath));
            System.out.printf("[+] [File] Entropy of encrypted file: %s \n",
                    CryptUtil.getFileShannonEntropy(encFilepath));

            if (CryptUtil.compareSha1(targetFilepath, decFilepath)) {
                System.out.println("[+] The decrypted file is the same as the source file");
            } else {
                System.out.println("[+] The decrypted file is different from the source file.");
                System.out.println("[+] $ cat '<decrypted file>' to to check the differences");
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

}


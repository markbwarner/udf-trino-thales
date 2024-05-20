/*
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package io.trino.plugin.thales;

import com.ingrian.security.nae.FPEParameterAndFormatSpec;
import com.ingrian.security.nae.FPEParameterAndFormatSpec.FPEParameterAndFormatBuilder;
import com.ingrian.security.nae.NAEKey;
import com.ingrian.security.nae.NAESession;
import io.airlift.slice.Slice;
import io.trino.spi.function.Description;
import io.trino.spi.function.ScalarFunction;
import io.trino.spi.function.SqlNullable;
import io.trino.spi.function.SqlType;
import io.trino.spi.type.StandardTypes;

import javax.crypto.Cipher;

public final class ThalesCADPFunctions
{
    private ThalesCADPFunctions() {}

    @ScalarFunction("cadp_encrypt_char")
    @Description("Returns FPE Encrypted data")
    @SqlType(StandardTypes.VARCHAR)
    public static String cadp_encrypt_char(@SqlNullable @SqlType(StandardTypes.VARCHAR) Slice inputstring)
    {
        String encdata = "";
        String tweakAlgo = null;
        String tweakData = null;

        NAESession session = null;
        try {
            String keyName = "testfaas";
            String userName = "apiuser";
            String password = "Yourpwd123!";
            //String userName =  System.getenv("CMUSER");
            //String password =  System.getenv("CMPWD");
            System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "/config/CADP_for_JAVA.properties");
            //System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "CADP_for_JAVA.properties");
            //IngrianProvider builder = new Builder().addConfigFileInputStream(getClass().getClassLoader().getResourceAsStream("CADP_for_JAVA.properties")).build();
            session = NAESession.getSession(userName, password.toCharArray());
            NAEKey key = NAEKey.getSecretKey(keyName, session);
            String algorithm = "FPE/FF1/CARD62";
            FPEParameterAndFormatSpec param = new FPEParameterAndFormatBuilder(tweakData).set_tweakAlgorithm(tweakAlgo).build();
            Cipher encryptCipher = Cipher.getInstance(algorithm, "IngrianProvider");
            // initialize cipher to encrypt.
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, param);
            // encrypt data
            byte[] outbuf = encryptCipher.doFinal(inputstring.getBytes());
            encdata = new String(outbuf);
        }
        catch (Exception e) {
            //     return "check exception";
        }
        finally {
            if (session != null) {
                session.closeSession();
            }
        }
        return (encdata);
    }

    @ScalarFunction("cadp_decrypt_char")
    @Description("Returns FPE Decrypted data")
    @SqlType(StandardTypes.VARCHAR)
    public static String cadp_decrypt_char(@SqlNullable @SqlType(StandardTypes.VARCHAR) Slice inputstring)
    {
        String decdata = "";
        String tweakAlgo = null;
        String tweakData = null;
        NAESession session = null;
        try {
            String keyName = "testfaas";
            String userName = "apiuser";
            String password = "Yourpwd123!";
            //String userName =  System.getenv("CMUSER");
            //String password =  System.getenv("CMPWD");
            System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "/config/CADP_for_JAVA.properties");
            //System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "CADP_for_JAVA.properties");
            //IngrianProvider builder = new Builder().addConfigFileInputStream(getClass().getClassLoader().getResourceAsStream("CADP_for_JAVA.properties")).build();
            session = NAESession.getSession(userName, password.toCharArray());
            NAEKey key = NAEKey.getSecretKey(keyName, session);
            String algorithm = "FPE/FF1/CARD62";
            FPEParameterAndFormatSpec param = new FPEParameterAndFormatBuilder(tweakData).set_tweakAlgorithm(tweakAlgo).build();
            Cipher decryptCipher = Cipher.getInstance(algorithm, "IngrianProvider");
            // initialize cipher to decrypt.
            decryptCipher.init(Cipher.DECRYPT_MODE, key, param);
            // decrypt data
            byte[] outbuf = decryptCipher.doFinal(inputstring.getBytes());
            decdata = new String(outbuf);
        }
        catch (Exception e) {
            //     return "check exception";
        }
        finally {
            if (session != null) {
                session.closeSession();
            }
        }

        return (decdata);
    }

    @ScalarFunction("cadp_encrypt_int")
    @Description("Returns FPE Encrypted data")
    @SqlType(StandardTypes.BIGINT)
    public static String cadp_encrypt_int(@SqlNullable @SqlType(StandardTypes.BIGINT) Slice inputstring)
    {
        String encdata = "";
        String tweakAlgo = null;
        String tweakData = null;

        NAESession session = null;
        try {
            String keyName = "testfaas";
            String userName = "apiuser";
            String password = "Yourpwd123!";
            //String userName =  System.getenv("CMUSER");
            //String password =  System.getenv("CMPWD");
            System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "/config/CADP_for_JAVA.properties");
            //System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "CADP_for_JAVA.properties");
            //IngrianProvider builder = new Builder().addConfigFileInputStream(getClass().getClassLoader().getResourceAsStream("CADP_for_JAVA.properties")).build();
            session = NAESession.getSession(userName, password.toCharArray());
            NAEKey key = NAEKey.getSecretKey(keyName, session);
            String algorithm = "FPE/FF1/CARD10";
            FPEParameterAndFormatSpec param = new FPEParameterAndFormatBuilder(tweakData).set_tweakAlgorithm(tweakAlgo).build();
            Cipher encryptCipher = Cipher.getInstance(algorithm, "IngrianProvider");
            // initialize cipher to encrypt.
            encryptCipher.init(Cipher.ENCRYPT_MODE, key, param);
            // encrypt data
            byte[] outbuf = encryptCipher.doFinal(inputstring.getBytes());
            encdata = new String(outbuf);
        }
        catch (Exception e) {
            //     return "check exception";
        }
        finally {
            if (session != null) {
                session.closeSession();
            }
        }

        return (encdata);
    }

    @ScalarFunction("cadp_decrypt_int")
    @Description("Returns FPE Decrypted data")
    @SqlType(StandardTypes.BIGINT)
    public static String cadp_decrypt_int(@SqlNullable @SqlType(StandardTypes.BIGINT) Slice inputstring)
    {
        String decdata = "";
        String tweakAlgo = null;
        String tweakData = null;
        NAESession session = null;
        try {
            String keyName = "testfaas";
            String userName = "apiuser";
            String password = "Yourpwd123!";
            //String userName =  System.getenv("CMUSER");
            //String password =  System.getenv("CMPWD");
            System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "/config/CADP_for_JAVA.properties");
            //System.setProperty("com.ingrian.security.nae.CADP_for_JAVA_Properties_Conf_Filename", "CADP_for_JAVA.properties");
            //IngrianProvider builder = new Builder().addConfigFileInputStream(getClass().getClassLoader().getResourceAsStream("CADP_for_JAVA.properties")).build();
            session = NAESession.getSession(userName, password.toCharArray());
            NAEKey key = NAEKey.getSecretKey(keyName, session);
            String algorithm = "FPE/FF1/CARD10";
            FPEParameterAndFormatSpec param = new FPEParameterAndFormatBuilder(tweakData).set_tweakAlgorithm(tweakAlgo).build();
            Cipher decryptCipher = Cipher.getInstance(algorithm, "IngrianProvider");
            // initialize cipher to decrypt.
            decryptCipher.init(Cipher.DECRYPT_MODE, key, param);
            // decrypt data
            byte[] outbuf = decryptCipher.doFinal(inputstring.getBytes());
            decdata = new String(outbuf);
        }
        catch (Exception e) {
            //     return "check exception";
        }
        finally {
            if (session != null) {
                session.closeSession();
            }
        }

        return (decdata);
    }
}

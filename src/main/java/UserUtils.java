import com.alibaba.fastjson.JSONObject;
import org.apache.commons.io.IOUtils;
import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;

import java.io.*;
import java.nio.charset.Charset;
import java.security.PrivateKey;

public class UserUtils {
    /**
     * Get private key from pem string
     * @param pemPrivateKey
     * @return
     * @throws IOException
     */
    public static PrivateKey getPrivateKeyFromPEMString(String pemPrivateKey) throws IOException {
        try (Reader pemReader = new StringReader(pemPrivateKey)) {
            PrivateKeyInfo pemPair = null;
            try (PEMParser pemParser = new PEMParser(pemReader)) {
                Object object = pemParser.readObject();
                if (object.getClass().equals(PrivateKeyInfo.class)) {
                    pemPair = (PrivateKeyInfo) object;
                } else if (object.getClass().equals(PEMKeyPair.class)) {
                    pemPair = ((PEMKeyPair) object).getPrivateKeyInfo();
                }
            }
            return new JcaPEMKeyConverter().getPrivateKey(pemPair);
        }
    }

    /**
     * Private key to PEM string
     * @param privateKey
     * @return
     * @throws IOException
     */
    public static String getPEMString(PrivateKey privateKey) throws IOException {
        StringWriter pemStrWriter = new StringWriter();
        try (JcaPEMWriter pemWriter = new JcaPEMWriter(pemStrWriter)) {
            pemWriter.writeObject(privateKey);
        }
        return pemStrWriter.toString();
    }

    public static SampleUser unSerializeUser(File file) throws IOException {
        SampleUser sampleUser = JSONObject.parseObject(IOUtils.toString(new FileInputStream(file),
                Charset.forName("utf-8")), SampleUser.class);
        sampleUser.setEnrollment(null);
        return sampleUser;
    }
}

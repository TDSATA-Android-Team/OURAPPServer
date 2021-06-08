package com.tdsata.ourappserver.util;

import org.springframework.web.context.request.async.DeferredResult;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.util.*;

/**
 * 主要API接口聚合类.
 *
 * <p>加密传输：服务器端生成RSA公钥私钥（1024位），客户端生成AES密钥（256位）；
 *            客户端使用AES密钥加密数据，使用RSA公钥加密AES密钥，上传到服务器端；
 *            服务器端使用RSA私钥解密出AES密钥，再解密出数据。</p>
 */
public class Server {
    private static final Tools.MyLog myLog = new Tools.MyLog(Server.class);

    public Server(String aesKeyStr) {
        decryptAESKey(aesKeyStr);
    }

    //***************加密传输*****************
    private static final List<RSAUpdateObserver> observers = new LinkedList<>();
    //-----------------AES------------------
    private byte[] aesKeyBytes = null;// AES密钥字节数组形式
    private Key aesKey = null;// AES密钥

    /**
     * 获得使用Base64编码的未加密AES密钥字符串.
     *
     * @return AES密钥字符串形式
     */
    public String getAESKeyNoEncrypt() {
        return new String(Base64.getEncoder().encode(aesKeyBytes), StandardCharsets.UTF_8);
    }

    /**
     * 检查是否缺少AES密钥.
     *
     * @return 若AES密钥为空则返回true，否则返回false
     */
    public boolean lackAESKey() {
        return aesKey == null;
    }

    /**
     * 使用AES密钥加密数据.
     *
     * @param data 待加密的数据
     * @return 加密后的密文，使用Base64编码
     */
    public String aesEncryptData(String data) {
        try {
            if (aesKey == null) {
                throw new NullPointerException("AES密钥为空");
            }
            if (data == null) {
                throw new NullPointerException("待加密数据为空");
            }
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.ENCRYPT_MODE, aesKey);
            return new String(Base64.getEncoder().encode(cipher.doFinal(data.getBytes())), StandardCharsets.UTF_8);
        } catch (Exception e) {
            myLog.e("AES加密数据失败", e);
            return null;
        }
    }

    /**
     * 使用AES密钥解密数据.
     *
     * @param ciphertext 待解密的使用Base64编码的密文
     * @return 解密后的数据
     */
    public String aesDecryptData(String ciphertext) {
        try {
            if (aesKey == null)
                throw new NullPointerException("AES密钥为空");
            if (ciphertext == null)
                throw new NullPointerException("待解密密文为空");
            byte[] decodeCiphertextBytes = Base64.getDecoder().decode(ciphertext.getBytes(StandardCharsets.UTF_8));
            Cipher cipher = Cipher.getInstance("AES");
            cipher.init(Cipher.DECRYPT_MODE, aesKey);
            return new String(cipher.doFinal(decodeCiphertextBytes), StandardCharsets.UTF_8);
        } catch (Exception e) {
            myLog.e("AES解密数据失败", e);
            return null;
        }
    }

    //-----------------RSA------------------
    private static final int rsaKeySize = 1024;// RSA密钥长度
    private static PrivateKey privateKey = null;// RSA私钥
    private static String publicKeyStr = null;// RSA公钥字符串形式

    /**
     * 生成RSA密钥对.
     */
    public synchronized static void generateRSAKeyPair() {
        try {
            KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
            rsa.initialize(rsaKeySize);
            KeyPair keyPair = rsa.generateKeyPair();
            privateKey = keyPair.getPrivate();
            byte[] publicKeyBytes = keyPair.getPublic().getEncoded();
            publicKeyStr = new String(Base64.getEncoder().encode(publicKeyBytes), StandardCharsets.UTF_8);
            // 通知观察者
            while (observers.size() > 0) {
                observers.get(0).awake();
                observers.remove(0);
            }
        } catch (Exception e) {
            myLog.e("生成RSA密钥对失败", e);
        }
    }

    /**
     * 获得RSA公钥的字符串形式，使用Base64编码.
     *
     * @return RSA公钥字符串
     */
    public static String getRSAPublicKeyStr() {
        return publicKeyStr;
    }

    /**
     * RSA私钥解密含密钥字符串以构造AES密钥.
     *
     * @param aesKeyStr 以Base64编码的RSA公钥加密后的AES密钥字符串
     */
    private void decryptAESKey(String aesKeyStr) {
        try {
            byte[] decodeAESKeyBytes = Base64.getDecoder().decode(aesKeyStr);
            int maxLength = rsaKeySize / 8;
            int mod = decodeAESKeyBytes.length % maxLength;
            int groupNum = decodeAESKeyBytes.length / maxLength;
            if (mod != 0) {
                groupNum++;
            }
            byte[][] dataSrc = new byte[groupNum][0];
            for (int i = 0, start = 0; i < groupNum; i++, start += maxLength) {
                if (i != groupNum - 1 || mod == 0) {
                    dataSrc[i] = Arrays.copyOfRange(decodeAESKeyBytes, start, start + maxLength);
                } else {
                    dataSrc[i] = Arrays.copyOfRange(decodeAESKeyBytes, start, start + mod);
                }
            }
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[][] cache = new byte[dataSrc.length][0];
            aesKeyBytes = new byte[0];
            for (int i = 0, start = 0; i < dataSrc.length; i++) {
                cache[i] = cipher.doFinal(dataSrc[i]);
                aesKeyBytes = Arrays.copyOf(aesKeyBytes, aesKeyBytes.length + cache[i].length);
                System.arraycopy(cache[i], 0, aesKeyBytes, start, cache[i].length);
                start = cache[i].length;
            }
            aesKey = new SecretKeySpec(aesKeyBytes, "AES");
        } catch (Exception e) {
            myLog.e("解密数据获取AES密钥失败", e);
        }
    }

    //--------------RSA更新观察者--------------
    public static void addRSAUpdateObserver(RSAUpdateObserver observer) {
        observers.add(observer);
    }

    public static class RSAUpdateObserver {
        private final DeferredResult<String> deferredResult;

        public RSAUpdateObserver(DeferredResult<String> deferredResult) {
            this.deferredResult = deferredResult;
        }

        public void awake() {
            deferredResult.setResult(Server.getRSAPublicKeyStr());
        }
    }

    //*****************邮件********************
    private Timer mailCodeTimer;// 邮件验证码线程

    /**
     * 使邮件验证码在一定时间后失效.
     */
    public void invalidMail(SQLTools sqlTools, Tools.DepartmentEnum department, String account) {
        stopMailCodeTimer();
        mailCodeTimer = new Timer();
        mailCodeTimer.schedule(new TimerTask() {
            @Override
            public void run() {
                try {
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                            SQLTools.tempKey, "");
                } catch (Exception e) {
                    // ignore
                }
            }
        }, 600000/*10分钟*/);
    }

    /**
     * 停止使邮件验证码无效的计时器任务.
     */
    public void stopMailCodeTimer() {
        if (mailCodeTimer != null) {
            mailCodeTimer.cancel();
            mailCodeTimer = null;
        }
    }
}

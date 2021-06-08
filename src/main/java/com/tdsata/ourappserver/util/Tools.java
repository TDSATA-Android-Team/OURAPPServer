package com.tdsata.ourappserver.util;

import com.github.aelstad.keccakj.fips202.SHA3_512;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Map;
import java.util.Random;

public class Tools {
    /**
     * 校验AES密钥是否正确.
     *
     * @param server 含有AES密钥的Server对象
     * @param verifyCiphertext 客户端使用AES密钥加密上传的"TD-SATA"密文
     * @return 若AES密钥准确则返回true，其余情况返回false
     */
    public static boolean verifyAESKey(Server server, String verifyCiphertext) {
        if (server.lackAESKey()) {
            return false;
        } else {
            return "TD-SATA".equals(server.aesDecryptData(verifyCiphertext));
        }
    }

    /**
     * 校验部门部长副部长身份.
     * 验证原理：在账号登录时，若身份标识含部长/副部长身份，则向temp字段存储AES密钥字符串；
     *         验证身份时，因客户端AES密钥在登录App时便仅生成一次且在App进程终止前保持不变，
     *         因此可通过验证账号所属temp字段中的AES密钥字符串是否与上传的AES密钥字符串一致
     *         来验证。
     *
     * @param server 含有AES密钥的Server对象
     * @param department 账号所属部门
     * @param account 处于加密状态的账号
     * @return 若确为部门部长副部长身份返回true，否则返回false
     */
    public static boolean verifyAdministrators(Server server, SQLTools sqlTools, DepartmentEnum department, String account) {
        account = server.aesDecryptData(account);
        Map<String, Object> user = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'", SQLTools.tempKey).get(0);
        return String.valueOf(user.get(SQLTools.tempKey)).equals(server.getAESKeyNoEncrypt());
    }

    //--------------------初始化数据库password和salt数据-----------------------
    private static final Random random = new Random(System.currentTimeMillis());

    /**
     * 随机生成一个长度在[20,30)区间的由大小写字母和数字组成的字符串.
     *
     * @return 生成的随机字符串
     */
    public static String getRandomSalt() {
        char[] chars = new char[20 + random.nextInt(30)];
        for (int i = 0; i < chars.length; i++) {
            switch (random.nextInt(3)) {
                case 0 -> chars[i] = (char) ('0' + random.nextInt(10));
                case 1 -> chars[i] = (char) ('A' + random.nextInt('Z' - 'A' + 1));
                case 2 -> chars[i] = (char) ('a' + random.nextInt('z' - 'a' + 1));
            }
        }
        return new String(chars);
    }

    /**
     * 获取通过Keccak512算法加密后的密码.
     *
     * @param password 原密码
     * @param salt 密码的加盐值
     * @return 加密后的结果
     */
    public static String getKeccak512Password(String password, String salt) {
        SHA3_512 keccak512 = new SHA3_512();
        return toHexString(keccak512.digest((password + salt).getBytes()));
    }

    /**
     * 获取通过MD5加密后的结果.
     *
     * @param data 原始数据
     * @return 加密结果
     */
    public static String getMD5(String data) {
        try {
            MessageDigest digest = MessageDigest.getInstance("MD5");
            return toHexString(digest.digest(data.getBytes(StandardCharsets.UTF_8)));
        } catch (NoSuchAlgorithmException e) {
            // ignore
            return data;
        }
    }

    private static String toHexString(byte[] data) {
        StringBuilder strHexString = new StringBuilder();
        for (byte aByte : data) {
            String hex = Integer.toHexString(0xff & aByte);
            if (hex.length() == 1) {
                strHexString.append('0');
            }
            strHexString.append(hex);
        }
        return strHexString.toString();
    }

    //--------------------------------内部类---------------------------------
    /**
     * 六部门枚举.
     */
    @SuppressWarnings("unused")
    public enum DepartmentEnum {
        SOFTWARE("software"), // 软研部
        NETWORK("network"),  // 网络部
        ELECTRON("electron"), // 电子部
        OFFICE("office"),   // 办公室
        PUBLICITY("publicity"),// 科宣部
        BUSINESS("business"); // 商务部

        private final String tableName;

        DepartmentEnum(String tableName) {
            this.tableName = tableName;
        }

        /**
         * 获取部门对应的主数据表表名.
         * 已通过 `表名` 引用.
         *
         * @return 部门主数据表表名
         */
        public String getTableName() {
            return "`" + tableName + "`";
        }

        /**
         * 获取部门对应的主数据表表名.
         * 不通过 `表名` 引用.
         *
         * @return 部门主数据表表名
         */
        public String getTableNameWithoutSymbol() {
            return tableName;
        }

        /**
         * 获取部门对应的签到活动统计表表名.
         * 已通过 `表名` 引用.
         *
         * @return 部门签到活动统计表表名
         */
        public String getSignInTableName() {
            return "`" + tableName + "_sign_in`";
        }

        /**
         * 获取部门对应的签到活动统计表表名.
         * 不通过 `表名` 引用.
         *
         * @return 部门签到活动统计表表名
         */
        public String getSignInTableNameWithoutSymbol() {
            return tableName + "_sign_in";
        }

        /**
         * 获取部门对应的公告信息表表名.
         * 已通过 `表名` 引用.
         *
         * @return 部门签到活动统计表表名
         */
        public String getAnnouncementTableName() {
            return "`" + tableName + "_announcement`";
        }

        /**
         * 获取部门对应的公告信息表表名.
         * 不通过 `表名` 引用.
         *
         * @return 部门签到活动统计表表名
         */
        public String getAnnouncementTableNameWithoutSymbol() {
            return tableName + "_announcement";
        }

        /**
         * 获取部门对应的积分变更记录表.
         * 已通过 `表名` 引用.
         *
         * @return 积分变更记录表表名
         */
        public String getChangeCountTableName() {
            return "`" + tableName + "_change_count`";
        }

        /**
         * 获取部门对应的积分变更记录表.
         * 不通过 `表名` 引用.
         *
         * @return 积分变更记录表表名
         */
        public String getChangeCountTableNameWithoutSymbol() {
            return tableName + "_change_count";
        }
    }

    /**
     * 日志工具包装类.
     */
    @SuppressWarnings("unused")
    public static class MyLog {
        private final Logger logger;
        private final String tag;

        public MyLog(Class<?> clazz) {
            this.logger = LoggerFactory.getLogger(clazz);
            this.tag = clazz.getSimpleName();
        }

        public void d(String errorInfo, Throwable throwable) {
            d(errorInfo + " (" + throwable.getClass().getSimpleName() + "): "
                    + throwable.getMessage());
        }

        public void i(String errorInfo, Throwable throwable) {
            i(errorInfo + " (" + throwable.getClass().getSimpleName() + "): "
                    + throwable.getMessage());
        }

        public void w(String errorInfo, Throwable throwable) {
            w(errorInfo + " (" + throwable.getClass().getSimpleName() + "): "
                    + throwable.getMessage());
        }

        public void e(String errorInfo, Throwable throwable) {
            e(errorInfo + " (" + throwable.getClass().getSimpleName() + "): "
                    + throwable.getMessage());
        }

        public void d(String message) {
            logger.debug(tag + " ==> " + message);
        }

        public void i(String message) {
            logger.info(tag + " ==> " + message);
        }

        public void w(String message) {
            logger.warn(tag + " ==> " + message);
        }

        public void e(String message) {
            logger.error(tag + " ==> " + message);
        }
    }
}

package com.tdsata.ourappserver.controller;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import com.tdsata.ourappserver.util.SQLTools;
import com.tdsata.ourappserver.util.Server;
import com.tdsata.ourappserver.util.Tools;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.context.request.async.DeferredResult;

import javax.imageio.ImageIO;
import javax.imageio.stream.ImageOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.*;

import static com.tdsata.ourappserver.util.SQLTools.tempKey;

@RestController("Server")
public class ServerController {
    private final Tools.MyLog myLog = new Tools.MyLog(ServerController.class);
    private final SQLTools sqlTools;
    private final Gson gson;
    private final SimpleDateFormat dateFormat;

    @Autowired
    public ServerController(JdbcTemplate jdbcTemplate) {
        sqlTools = new SQLTools(jdbcTemplate);
        gson = new Gson();
        dateFormat = new SimpleDateFormat("yyyy-MM-dd HH:mm", Locale.CHINA);
    }

    //*************************初始化连接与实时更新客户端RSA公钥****************************
    /**
     * App登录时进行的连接初始化.
     */
    @GetMapping(value = "initConnection")
    public String initConnection() {
        return Server.getRSAPublicKeyStr();
    }

    /**
     * 连接初始化后保持App持有的服务器RSA公钥实时更新.
     */
    @GetMapping("updateRSAPublicKey")
    public DeferredResult<String> updateRSAPublicKey() {
        DeferredResult<String> deferredResult = new DeferredResult<>(630000L/*10m30s超时*/, "Timeout");
        Server.addRSAUpdateObserver(new Server.RSAUpdateObserver(deferredResult));
        return deferredResult;
    }

    //**************************************敏感数据传输********************************************
    // 流程（设计依据：AES加解密效率高于RSA加解密效率，利于较大数据的传输）：
    // 上传：AES密钥密文（使用RSA公钥加密）、校验AES密钥的校验密文（客户端使用AES密钥加密"TD-SATA"文本生成的密文）、
    //      敏感数据密文（客户端使用AES加密敏感数据生成的密文）
    // 使用：使用RSA私钥解密出AES密钥 --> 校验AES密钥 --> 解密敏感数据
    /**
     * 使用账号和密码进行登录.
     *
     * @param aesKeyStr 使用RSA公钥加密的含AES密钥字符串（下同）
     * @param verifyCiphertext 客户端使用AES密钥加密“TD-SATA”后生成的加密结果（下同）
     * @param departmentJson 处于加密状态（使用AES密钥加密）的部门的Json字段（下同）
     * @param account 处于加密状态（使用AES密钥加密）的账号（下同）
     * @param password 处于加密状态（使用AES密钥加密）的密码（客户端使用Keccak512加密原密码后生成的密码）
     */
    @PostMapping(value = "login")
    public String login(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String password) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                password = server.aesDecryptData(password);
                List<Map<String, Object>> list = sqlTools.queryDBTable(department.getTableName(),
                        "number = '" + account + "'", "password", "salt", "flag");
                if (list != null) {
                    Map<String, Object> user = list.get(0);
                    if (String.valueOf(user.get("password")).equals(Tools.getKeccak512Password(password, String.valueOf(user.get("salt"))))) {
                        list = sqlTools.queryDBTable(department.getTableName(), null,
                                "name", "number", "subject", "phone", "teacher", "qq", "sex", "count", "flag", "photo_path");
                        if (list != null) {
                            String userFlag = String.valueOf(user.get("flag"));
                            if (userFlag.contains("2"/*副部长*/) || userFlag.contains("3"/*部长*/)) {// 登录账户为副部长或部长
                                sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'", tempKey, server.getAESKeyNoEncrypt());
                            }
                            replacePhotoName(list);
                            return server.aesEncryptData(gson.toJson(list));
                        } else {// ignore
                            return "ERROR";
                        }
                    } else {
                        return "PASSWORD_ERROR";
                    }
                } else {
                    return "ACCOUNT_NO_EXIST";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("登录发生异常", e);
            return "ERROR";
        }
    }

    /**
     * 刷新客户端成员数据列表.
     */
    @PostMapping(value = "refreshMembers")
    public String refreshMembers(String aesKeyStr, String verifyCiphertext, String departmentJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                List<Map<String, Object>> queryList = sqlTools.queryDBTable(department.getTableName(), null,
                        "name", "number", "subject", "phone", "teacher", "qq", "sex", "count", "flag", "photo_path");
                if (queryList != null) {
                    replacePhotoName(queryList);
                    return server.aesEncryptData(gson.toJson(queryList));
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("刷新客户端成员数据列表发生异常", e);
        }
        return "ERROR";
    }

    private void replacePhotoName(List<Map<String, Object>> list) {
        for (Map<String, Object> map : list) {
            String path = String.valueOf(map.get("photo_path"));
            map.put("photoName", path.substring(path.lastIndexOf("/") + 1));
            map.remove("photo_path");
        }
    }

    /**
     * 请求验证填写的邮件验证码是否正确.
     *
     * @param inputMailCode 处于加密状态（使用AES密钥加密）的用户输入的邮件验证码
     */
    @PostMapping(value = "verifyMailCode")
    public String verifyMailCode(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String inputMailCode) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                inputMailCode = server.aesDecryptData(inputMailCode);
                Map<String, Object> map = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        tempKey).get(0);
                String mailCode = String.valueOf(map.get(tempKey));
                server.stopMailCodeTimer();
                boolean isRight = mailCode.equals(inputMailCode);
                if (isRight) {
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                            tempKey, "true");
                }
                return String.valueOf(isRight);
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("验证邮件验证码发生异常", e);
            return "false";
        }
    }

    /**
     * 通过邮件验证码验证后修改密码.
     *
     * @param newPassword 处于加密状态（使用AES密钥加密）的新密码（客户端使用Keccak512加密原新密码后生成的密码）
     */
    @PostMapping(value = "alterPasswordUseMail")
    public String alterPasswordUseMail(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String newPassword) {
        Tools.DepartmentEnum department = null;
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                newPassword = server.aesDecryptData(newPassword);
                Map<String, Object> map = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        tempKey).get(0);
                if (Boolean.parseBoolean(String.valueOf(map.get("temp")))) {
                    String salt = Tools.getRandomSalt();
                    newPassword = Tools.getKeccak512Password(newPassword, salt);
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                            "password", newPassword, "salt", salt, tempKey, "");
                    return "OK";
                } else {
                    return "ILLEGAL";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("修改密码发生异常", e);
            if (department != null) {
                try {
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'", tempKey, "true");
                } catch (Exception exception) {
                    // ignore
                }
            }
            return "ERROR";
        }
    }

    /**
     * 添加签到活动.
     * 需验证部门部长副部长身份.
     *
     * @param activityTitle 签到活动标题，30个（含）字符以内
     * @param signInTime 签到开始时间（yyyy-MM-dd HH:mm）
     * @param continueTime 有效时间，整型数据（单位：分钟）
     */
    @PostMapping("addSignInActivity")
    public String addSignInActivity(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                                     String activityTitle, String signInTime, String continueTime) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    activityTitle = server.aesDecryptData(activityTitle);
                    if (activityTitle.length() > 30) {
                        return "ADD_FAIL";
                    }
                    signInTime = server.aesDecryptData(signInTime);
                    dateFormat.parse(signInTime);// 校验时间格式
                    continueTime = server.aesDecryptData(continueTime);
                    if (Integer.parseInt(continueTime)/*校验整型数据*/ < 0) {
                        return "ADD_FAIL";
                    }
                    if (sqlTools.queryDBTable(SQLTools.signInActivityInfo, "title = '" + activityTitle + "'", "*") != null) {
                        return "ACTIVITY_ALREADY_EXIST";
                    }
                    sqlTools.insertDataInDBTable(SQLTools.signInActivityInfo,
                            "title", activityTitle, "signInTime", signInTime, "continueTime", continueTime);
                    String id = String.valueOf(sqlTools.queryDBTable(SQLTools.signInActivityInfo,
                            "title = '" + activityTitle + "'", "id").get(0).get("id"));
                    sqlTools.addFieldOnTable(department.getSignInTableName(), "`" + id + "` int", "not null", "0", null, null);
                    return "ADD_SUCCESS";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("添加签到活动发生异常", e);
        }
        return "ADD_FAIL";
    }

    /**
     * 删除多个签到活动.
     * 需验证部门部长副部长身份.
     *
     * @param activityTitlesJson 签到活动标题数组的Json字符串
     * @return 若未发生异常，则返回一个布朗数组的Json字符串，其中元素与活动标题一一对应，
     *         true表示对应活动删除成功，false则表示对应活动删除失败
     */
    @PostMapping("delSignInActivities")
    public String delSignInActivities(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String activityTitlesJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    activityTitlesJson = server.aesDecryptData(activityTitlesJson);
                    String[] titles = gson.fromJson(activityTitlesJson, String[].class);
                    boolean[] results = new boolean[titles.length];
                    for (int i = 0; i < titles.length; i++) {
                        try {
                            List<Map<String, Object>> query = sqlTools.queryDBTable(SQLTools.signInActivityInfo, "title = '" + titles[i] + "'", "id");
                            if (query == null) {// 活动不存在或已删除
                                results[i] = false;
                                continue;
                            }
                            String id = String.valueOf(query.get(0).get("id"));
                            sqlTools.delDataFromDBTable(SQLTools.signInActivityInfo, "title = '" + titles[i] + "'");
                            sqlTools.delFieldOnTable(department.getSignInTableName(), "`" + id + "`");
                            results[i] = true;
                        } catch (Exception e) {
                            results[i] = false;
                        }
                    }
                    return gson.toJson(results);
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("删除签到活动发生异常", e);
        }
        return "DEL_FAIL";
    }

    /**
     * 设置多个部员的签到状态.
     * 需验证部门部长副部长身份.
     *
     * @param activityTitle 签到活动标题
     * @param multipleSignInNumberJson 多个签到部员的学号
     * @param multipleSignInStatusJson 多个签到部员的签到状态，需与学号一一对应
     */
    @PostMapping("setMultipleSignInStatus")
    public String setMultipleSignInStatus(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                                          String activityTitle, String multipleSignInNumberJson, String multipleSignInStatusJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    String[] signInNumber = gson.fromJson(server.aesDecryptData(multipleSignInNumberJson), String[].class);
                    String[] signInStatus = gson.fromJson(server.aesDecryptData(multipleSignInStatusJson), String[].class);
                    if (signInNumber.length == signInStatus.length) {
                        activityTitle = server.aesDecryptData(activityTitle);
                        List<String> statusOne = new LinkedList<>();
                        List<String> statusTwo = new LinkedList<>();
                        for (int i = 0; i < signInNumber.length; i++) {
                            switch (signInStatus[i]) {
                                case "1":// 已签到
                                    statusOne.add(signInNumber[i]);
                                    break;
                                case "2":// 已签到但迟到
                                    statusTwo.add(signInNumber[i]);
                                    break;
                                default:
                                    return "ERROR";
                            }
                        }
                        List<Map<String, Object>> queryId = sqlTools.queryDBTable(SQLTools.signInActivityInfo,
                                "title = '" + activityTitle + "'", "id");
                        if (queryId == null) {
                            return "ACTIVITY_NOT_EXIST";
                        }
                        String id = String.valueOf(queryId.get(0).get("id"));
                        setStatus(department, id, statusOne, "1");
                        setStatus(department, id, statusTwo, "2");
                        return "OK";
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("设置多个部员的签到状态发生异常", e);
        }
        return "ERROR";
    }

    private void setStatus(Tools.DepartmentEnum department, String activityId, List<String> numbers, String status) throws Exception {
        int id = Integer.parseInt(activityId);// 校验获取的活动id是否异常
        int size = numbers.size();
        if (size > 0) {
            StringBuilder inCondition = new StringBuilder("`number` in (");
            for (int i = 0; i < size; i++) {
                inCondition.append("'").append(numbers.get(i)).append("'");
                if (i < size - 1) {
                    inCondition.append(", ");
                }
            }
            inCondition.append(") and `").append(id).append("` = '0'");
            sqlTools.updateDataForDBTable(department.getSignInTableName(), String.valueOf(inCondition),
                    "`" + id + "`", status);
        }
    }

    /**
     * 获取指定签到活动的部员签到状态.
     *
     * @param activityTitle 指定的签到活动标题
     */
    @PostMapping("getSignInStatusList")
    public String getSignInStatusList(String aesKeyStr, String verifyCiphertext, String departmentJson, String activityTitle) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                activityTitle = server.aesDecryptData(activityTitle);
                List<Map<String, Object>> queryId = sqlTools.queryDBTable(SQLTools.signInActivityInfo,
                        "title = '" + activityTitle + "'", "id");
                if (queryId == null) {
                    return "ACTIVITY_NOT_EXIST";
                }
                String id = String.valueOf(queryId.get(0).get("id"));
                String idKey = String.valueOf(Integer.parseInt(id));// 校验获取的id
                List<Map<String, Object>> queryList = sqlTools.queryDBTable(department.getSignInTableName(),
                        "number not in (select number from software where locate('3', flag) > 0 or locate('2', flag) > 0)",
                        "`number`", "`name`", "`" + idKey + "`");
                if (queryList != null) {
                    for (Map<String, Object> map : queryList){
                        map.put("signInStatus", map.get(idKey));
                        map.remove(idKey);
                    }
                    return server.aesEncryptData(gson.toJson(queryList));
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取签到状态列表失败", e);
        }
        return "ERROR";
    }

    /**
     * 获取指定学号的部员在指定的签到活动的签到状态.
     *
     * @param activityTitle 活动标题
     */
    @PostMapping("getSignInStatus")
    public String getSignInStatus(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String activityTitle) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                activityTitle = server.aesDecryptData(activityTitle);
                List<Map<String, Object>> queryId = sqlTools.queryDBTable(SQLTools.signInActivityInfo,
                        "title = '" + activityTitle + "'", "id");
                if (queryId == null) {
                    return "ACTIVITY_NOT_EXIST";
                }
                String idStr = String.valueOf(queryId.get(0).get("id"));
                int id = Integer.parseInt(idStr);
                List<Map<String, Object>> queryStatus = sqlTools.queryDBTable(department.getSignInTableName(),
                        "number = '" + account + "'", "`" + id + "`");
                if (queryStatus != null) {
                    return String.valueOf(queryStatus.get(0).get(String.valueOf(id)));
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取指定学号的部员在指定的签到活动的签到状态发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取活动列表.
     */
    @PostMapping("getSignInActivities")
    public String getSignInActivities(String aesKeyStr, String verifyCiphertext, String departmentJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                String[] activityIds = sqlTools.queryFieldName(department.getSignInTableNameWithoutSymbol(),
                        "number", "name", "id");
                if (activityIds == null) {
                    return "HAS_NOT_ACTIVITY";
                }
                StringBuffer condition = new StringBuffer();
                for (int i = 0; i < activityIds.length; i++) {
                    condition.append("id = '").append(activityIds[i]).append("'");
                    if (i < activityIds.length - 1) {
                        condition.append(" or ");
                    }
                }
                List<Map<String, Object>> queryResult = sqlTools.queryDBTable(SQLTools.signInActivityInfo, String.valueOf(condition),
                        "title", "signInTime", "continueTime");
                if (queryResult == null) {
                    return "HAS_NOT_ACTIVITY";
                }
                return server.aesEncryptData(gson.toJson(queryResult));
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取签到活动发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 通过常规方式修改密码.
     *
     * @param oldPassword 旧密码的Keccak512密文
     * @param newPassword 新密码的Keccak512密文
     */
    @PostMapping("alterPassword")
    public String alterPassword(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String oldPassword, String newPassword) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                oldPassword = server.aesDecryptData(oldPassword);
                Map<String, Object> user = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        "password", "salt").get(0);
                if (String.valueOf(user.get("password")).equals(Tools.getKeccak512Password(oldPassword, String.valueOf(user.get("salt"))))) {
                    newPassword = server.aesDecryptData(newPassword);
                    String newSalt = Tools.getRandomSalt();
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                            "salt", newSalt, "password", Tools.getKeccak512Password(newPassword, newSalt));
                    return "OK";
                } else {
                    return "PASSWORD_ERROR";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("通过常规方式修改密码发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 上传头像.
     *
     * @param photoText 图片转化的Base64编码
     */
    @PostMapping("uploadHeadPhoto")
    public String uploadHeadPhoto(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String photoText) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                photoText = server.aesDecryptData(photoText);
                byte[] picData = Base64.getDecoder().decode(photoText.getBytes(StandardCharsets.UTF_8));
                if (picData.length > 500 * 1024/*500KB*/) {// 限制图片大小在500KB以内
                    return "PIC_TOO_BIG";
                }
                String directory = "C:/Users/Administrator/MyFile/SpringBoot/OURAPPServer/HeadPhoto/" + department.name().toLowerCase();
                File dir = new File(directory);
                if (dir.exists() || dir.mkdirs()) {
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                            "photo_path");
                    if (query != null) {
                        Map<String, Object> user = query.get(0);
                        String path = String.valueOf(user.get("photo_path"));
                        if (!(path.equals("null") || path.equals("default_photo"))) {
                            File pic = new File(path);
                            if (pic.exists() && pic.delete()) {
                                myLog.d("文件：" + pic.getAbsolutePath() + "已删除");
                            }
                        }
                        String filename = Tools.getMD5(account).substring(0, 8) + Tools.getMD5(String.valueOf(System.currentTimeMillis())).substring(0, 8);
                        File photo = new File(directory, filename);
                        try (ImageOutputStream ios = ImageIO.createImageOutputStream(photo)) {
                            ios.write(picData);
                        }
                        sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                                "photo_path", photo.getAbsolutePath().replace("\\", "/"));
                        return server.aesEncryptData(filename);
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("上传头像中发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取多个学号对应的头像.
     *
     * @param numbersJson 由多个学号组成的字符串数组的Json格式
     */
    @PostMapping("getHeadPhotos")
    public String getHeadPhotos(String aesKeyStr, String verifyCiphertext, String departmentJson, String numbersJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                String[] numbers = gson.fromJson(server.aesDecryptData(numbersJson), String[].class);
                if (numbers.length > 0) {
                    StringBuilder condition = new StringBuilder("number in (");
                    for (int i = 0; i < numbers.length; i++) {
                        condition.append("'").append(numbers[i]).append("'");
                        if (i < numbers.length - 1) {
                            condition.append(", ");
                        }
                    }
                    condition.append(")");
                    List<Map<String, Object>> queryList = sqlTools.queryDBTable(department.getTableName(), condition.toString(), "number", "photo_path");
                    if (queryList != null) {
                        Map<String, String> result = new HashMap<>();
                        for (Map<String, Object> map : queryList) {
                            String key = String.valueOf(map.get("number"));
                            if (key.equals("null")) {
                                continue;
                            }
                            String path = String.valueOf(map.get("photo_path"));
                            if (path.equals("null") || path.equals("default_photo")) {
                                result.put(key, "default_photo");
                            } else {
                                try {
                                    File pic = new File(path);
                                    try (FileInputStream fis = new FileInputStream(pic)) {
                                        long bytes = pic.length();
                                        byte[] picData = new byte[bytes <= Integer.MAX_VALUE ? (int) bytes : 0];
                                        if (picData.length != 0 && fis.read(picData) > 0) {
                                            String photoText = new String(Base64.getEncoder().encode(picData), StandardCharsets.UTF_8);
                                            result.put(key, photoText);
                                        } else {
                                            result.put(key, "default_photo");
                                        }
                                    }
                                } catch (IOException e) {
                                    result.put(key, "default_photo");
                                }
                            }
                        }
                        return server.aesEncryptData(gson.toJson(result));
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取多个学号对应的头像发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 添加公告.
     * 需验证部门部长副部长身份.
     *
     * @param message 公告内容
     */
    @PostMapping("addAnnouncement")
    public String addAnnouncement(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String message) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    account = server.aesDecryptData(account);
                    message = server.aesDecryptData(message);
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getAnnouncementTableName(),
                            "message = '" + message + "'", "*");
                    if (query != null) {
                        return "ANNOUNCEMENT_ALREADY_EXISTS";
                    }
                    sqlTools.insertDataInDBTable(department.getAnnouncementTableName(),
                            "number", account, "message", message);
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("添加公告发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 删除公告.
     * 需验证部门部长副部长身份.
     *
     * @param id 公告id
     */
    @PostMapping("delAnnouncement")
    public String delAnnouncement(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String id) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    id = server.aesDecryptData(id);
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getAnnouncementTableName(),
                            "id = '" + id + "'", "*");
                    if (query == null) {
                        return "ANNOUNCEMENT_NOT_EXISTS";
                    }
                    sqlTools.delDataFromDBTable(department.getAnnouncementTableName(), "id = '" + id + "'");
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("删除公告发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取公告列表.
     */
    @PostMapping("getAnnouncementList")
    public String getAnnouncementList(String aesKeyStr, String verifyCiphertext, String departmentJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                List<Map<String, Object>> query = sqlTools.queryDBTable(department.getAnnouncementTableName(), null,
                        "id", "number", "message");
                if (query != null) {
                    return server.aesEncryptData(gson.toJson(query));
                } else {
                    return "NO_ANNOUNCEMENT";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取公告列表发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 修改积分.
     * 需验证部门部长副部长身份.
     *
     * @param toNumber 被修改者的学号
     * @param changeValue 改变的值（实为有符号整型数据）
     */
    @PostMapping("changeCount")
    public String changeCount(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                              String toNumber, String changeValue, String description) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    account = server.aesDecryptData(account);
                    toNumber = server.aesDecryptData(toNumber);
                    int change = Integer.parseInt(server.aesDecryptData(changeValue));
                    description = server.aesDecryptData(description);
                    if ("".equals(description)) {
                        description = "no-description";
                    }
                    sqlTools.insertDataInDBTable(department.getChangeCountTableName(),
                            "editor_number", account, "change_number", toNumber,
                            "change_value", String.valueOf(change), "description", description);
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(),
                            "number = '" + toNumber + "'", "count");
                    if (query != null) {
                        int count = Integer.parseInt(String.valueOf(query.get(0).get("count")));
                        count += change;
                        sqlTools.updateDataForDBTable(department.getTableName(),
                                "number = '" + toNumber + "'", "count", String.valueOf(count));
                        return "OK";
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("修改积分发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取积分修改记录.
     * 需验证部门部长副部长身份.
     */
    @PostMapping("getChangeCountHistory")
    public String getChangeCountHistory(String aesKeyStr, String verifyCiphertext, String departmentJson, String account) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getChangeCountTableName(), null,
                            "editor_number", "change_number", "change_value", "description");
                    if (query == null) {
                        return "NO_HISTORY";
                    } else {
                        return server.aesEncryptData(gson.toJson(query));
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取积分修改记录发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 添加或更新部门信息.
     * 需验证部门部长副部长身份.
     *
     * @param info 添加或更新的信息
     */
    @PostMapping("addDepartmentInfo")
    public String addDepartmentInfo(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                                    String info) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    info = server.aesDecryptData(info);
                    String departmentName = department.name();
                    List<Map<String, Object>> query = sqlTools.queryDBTable(SQLTools.departmentInfo,
                            "department = '" + departmentName + "'", "*");
                    if (query == null) {
                        sqlTools.insertDataInDBTable(SQLTools.departmentInfo,
                                "department", departmentName, "info", info);
                    } else {
                        sqlTools.updateDataForDBTable(SQLTools.departmentInfo, "department = '" + departmentName + "'",
                                "info", info);
                    }
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("添加或更新部门信息发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取部门介绍.
     */
    @PostMapping("getDepartmentInfo")
    public String getDepartmentInfo(String aesKeyStr, String verifyCiphertext, String departmentJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                List<Map<String, Object>> query = sqlTools.queryDBTable(SQLTools.departmentInfo, "department = '" + department.name() + "'",
                        "info");
                if (query == null) {
                    return server.aesEncryptData("no-info");
                } else {
                    return server.aesEncryptData(String.valueOf(query.get(0).get("info")));
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取部门介绍发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 修改或完善个人信息.
     *
     * @param subject 专业
     * @param sex 性别
     * @param phone 电话
     * @param qq QQ
     * @param teacher 辅导员
     * @param email 邮箱
     */
    @PostMapping("uploadPersonalInfo")
    public String uploadPersonalInfo(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                                     String subject, String sex, String phone, String qq, String teacher, String email) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                subject = server.aesDecryptData(subject);
                sex = server.aesDecryptData(sex);
                phone = server.aesDecryptData(phone);
                qq = server.aesDecryptData(qq);
                teacher = server.aesDecryptData(teacher);
                email = server.aesDecryptData(email);
                if ("".equals(email)) {
                    email = "no-mail";
                } else {
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                            "mail", "mail_enable");
                    if (query != null) {
                        Map<String, Object> user = query.get(0);
                        String srcMail = String.valueOf(user.get("mail"));
                        String mailEnable = String.valueOf(user.get("mail_enable"));
                        if (!("1".equals(mailEnable) && email.equals(srcMail))) {
                            sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                                    "mail_enable", "0");
                        }
                    }
                }
                sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                        "subject", subject, "sex", sex, "phone", phone,
                        "qq", qq, "teacher", teacher, "mail", email, "info_enable", "1");
                return "OK";
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("上传个人信息发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取信息完善标识.
     */
    @PostMapping("getEnable")
    public String getEnable(String aesKeyStr, String verifyCiphertext, String departmentJson, String account) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        "info_enable", "mail_enable", "mail");
                if (query != null) {
                    Map<String, Object> user = query.get(0);
                    String infoEnable = String.valueOf(user.get("info_enable"));
                    String mailEnable = String.valueOf(user.get("mail_enable"));
                    String mail = String.valueOf(user.get("mail"));
                    if (!(infoEnable.equals("null") || mailEnable.equals("null") || mail.equals("null"))) {
                        Map<String, String> result = new HashMap<>();
                        result.put("info_enable", infoEnable);
                        result.put("mail_enable", mailEnable);
                        result.put("mail", mail);
                        return server.aesEncryptData(gson.toJson(result));
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("获取信息完善标识发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 添加部门成员.
     * 需验证部门部长副部长身份.
     *
     * @param number 所添加成员的学号
     * @param name 所添加成员的姓名
     * @param flagsJson 所添加成员的身份标识数组的Json字符串
     */
    @PostMapping("addMember")
    public String addMember(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                            String number, String name, String flagsJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    number = server.aesDecryptData(number);
                    Integer.parseInt(number);// 简单校验学号
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + number + "'", "*");
                    if (query != null) {
                        return "MEMBER_ALREADY_EXISTS";
                    }
                    name = server.aesDecryptData(name);
                    String flag = getFlagString(server, flagsJson);
                    String password;
                    if (flag.contains("3")/*部长*/ || flag.contains("2")/*副部长*/) {
                        password = "TD_SATA";
                    } else {
                        password = "TD-SATA";
                    }
                    String salt = Tools.getRandomSalt();
                    password = Tools.getKeccak512Password(Tools.getKeccak512Password(password, ""), salt);
                    sqlTools.insertDataInDBTable(department.getTableName(), "number", number, "name", name,
                            "flag", flag, "password", password, "salt", salt);
                    sqlTools.executeAny("insert " + department.getSignInTableName() + " (id, number, name) select id, number, name from "
                            + department.getTableName() + " where number = '" + number + "'");
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("添加部门成员发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 移除部门成员.
     * 需验证部门部长副部长身份.
     *
     * @param number 所移除的部门成员的学号
     */
    @PostMapping("delMember")
    public String delMember(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String number) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    number = server.aesDecryptData(number);
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + number + "'", "*");
                    if (query == null) {
                        return "MEMBER_NOT_EXISTS";
                    }
                    sqlTools.delDataFromDBTable(department.getTableName(), "number = '" + number + "'");
                    sqlTools.delDataFromDBTable(department.getAnnouncementTableName(), "number = '" + number + "'");
                    sqlTools.delDataFromDBTable(department.getChangeCountTableName(),
                            "change_number = '" + number + "'");
                    String photoPath = String.valueOf(query.get(0).get("photo_path"));
                    if (!(photoPath.equals("null") || photoPath.equals("default_photo"))) {
                        File photo = new File(photoPath);
                        if (photo.exists()) {
                            if (!photo.delete()) {
                                myLog.d("文件" + photo.getAbsolutePath() + "删除失败");
                            }
                        }
                    }
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("移除部门成员发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 更新部门成员信息.
     * 需验证部门部长副部长身份.
     *
     * @param oldNumber 待更新部门成员的旧学号
     * @param number 待更新部门成员的新学号
     * @param name 待更新部门成员的新信息
     * @param flagsJson 待更新部门成员的新身份标识数组的Json字符串
     */
    @PostMapping("updateMember")
    public String updateMember(String aesKeyStr, String verifyCiphertext, String departmentJson, String account,
                               String oldNumber, String number, String name, String flagsJson) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                if (Tools.verifyAdministrators(server, sqlTools, department, account)) {
                    File oldPhoto = null;
                    oldNumber = server.aesDecryptData(oldNumber);
                    List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + oldNumber + "'", "*");
                    if (query == null) {
                        return "MEMBER_NOT_EXISTS";
                    }
                    number = server.aesDecryptData(number);
                    if (!oldNumber.equals(number)) {
                        String photoPath = String.valueOf(query.get(0).get("photo_path"));
                        if (!(photoPath.equals("null") || photoPath.equals("default_photo"))) {
                            oldPhoto = new File(photoPath);
                            oldPhoto = oldPhoto.exists() ? oldPhoto : null;
                        }
                        query = sqlTools.queryDBTable(department.getTableName(), "number = '" + number + "'", "*");
                        if (query != null) {
                            return "MEMBER_ALREADY_EXISTS_IF_UPDATE";
                        }
                    }
                    name = server.aesDecryptData(name);
                    String flag = getFlagString(server, flagsJson);
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + oldNumber + "'",
                            "number", number, "name", name, "flag", flag);
                    sqlTools.updateDataForDBTable(department.getAnnouncementTableName(),
                            "number = '" + oldNumber + "'", "number", number);
                    sqlTools.updateDataForDBTable(department.getChangeCountTableName(),
                            "editor_number = '" + oldNumber + "'", "editor_number", number);
                    sqlTools.updateDataForDBTable(department.getChangeCountTableName(),
                            "change_number = '" + oldNumber + "'", "change_number", number);
                    if (oldPhoto != null) {
                        String path = oldPhoto.getAbsolutePath();
                        String filename = oldPhoto.getName();
                        filename = Tools.getMD5(number).substring(0, 8) + filename.substring(8);
                        if (!oldPhoto.renameTo(new File(path, filename))) {
                            myLog.d("文件" + oldPhoto.getAbsolutePath() + "重命名为" + path + "\\" + filename + "失败");
                        }
                    }
                    return "OK";
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("更新部门成员信息发生异常", e);
        }
        return "ERROR";
    }

    private String getFlagString(Server server, String flagsJson) {
        Set<String> flagSet = gson.fromJson(server.aesDecryptData(flagsJson),
                new TypeToken<Set<String>>() {}.getType());// 去重
        String[] flags = flagSet.toArray(new String[0]);
        StringBuilder flag = new StringBuilder();
        for (int i = 0; i < flags.length; i++) {
            switch (flags[i]) {
                case "0"/*部员*/, "1"/*组长*/, "2"/*副部长*/, "3"/*部长*/ -> flag.append(flags[i]);
                default -> flag.append("0");
            }
            if (i < flags.length - 1) {
                flag.append(",");
            }
        }
        if (flag.isEmpty()) {
            flag.append("0");
        }
        return flag.toString();
    }

    /**
     * 验证电子邮件.
     * 参数名目的为隐藏值的意义.
     *
     * @param number 验证者学号
     * @param v1 验证者部门，已用Keccak512加密
     * @param v2 电子邮件，已用Keccak512加密
     */
    @GetMapping("verifyEmail")
    public String verifyTheEmail(String number, String v1, String v2) {
        try {
            Tools.DepartmentEnum[] departments = Tools.DepartmentEnum.values();
            Tools.DepartmentEnum department = null;
            for (Tools.DepartmentEnum the : departments) {
                if (v1.equals(Tools.getKeccak512Password(the.name(), ""))) {
                    department = the;
                }
            }
            if (department == null) {
                return "链接错误";
            }
            List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(),
                    "number = '" + number + "'", "mail", "mail_enable", "mail_verify_time");
            if (query != null) {
                Map<String, Object> user = query.get(0);
                if (v2.equals(Tools.getKeccak512Password(String.valueOf(user.get("mail")), ""))) {
                    if ("1".equals(String.valueOf(user.get("mail_enable")))) {
                        return "已验证";
                    }
                    long time = Long.parseLong(String.valueOf(user.get("mail_verify_time")));
                    if (System.currentTimeMillis() - time > 24 * 60 * 60000/*24小时*/) {
                        return "链接已失效";
                    }
                    sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + number + "'",
                            "mail_enable", "1");
                    return "验证成功";
                }
            }
        } catch (Exception e) {
            myLog.e("验证电子邮件发送异常", e);
        }
        return "验证失败";
    }
}

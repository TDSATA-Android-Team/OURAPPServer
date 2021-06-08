package com.tdsata.ourappserver.controller;

import com.google.gson.Gson;
import com.tdsata.ourappserver.util.SQLTools;
import com.tdsata.ourappserver.util.Server;
import com.tdsata.ourappserver.util.Tools;
import freemarker.template.Configuration;
import freemarker.template.Template;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.mail.javamail.MimeMessageHelper;
import org.springframework.ui.ModelMap;
import org.springframework.ui.freemarker.FreeMarkerTemplateUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.activation.DataSource;
import javax.mail.internet.MimeMessage;
import javax.mail.util.ByteArrayDataSource;
import java.io.IOException;
import java.io.InputStream;
import java.util.List;
import java.util.Map;
import java.util.Random;

@RestController("Email")
public class EmailController {
    private final Tools.MyLog myLog = new Tools.MyLog(EmailController.class);
    private final JavaMailSender javaMailSender;
    private final JdbcTemplate jdbcTemplate;
    private final Configuration configuration;
    private final Random random;
    private final Gson gson;
    @Value("#{T(org.springframework.util.ClassUtils).getDefaultClassLoader()}")
    private ClassLoader classLoader;
    @Value("${spring.mail.username}")
    private String fromEmail;// 邮件的发送者
    private final String mailSubject;// 邮件主题

    @Autowired
    public EmailController(JavaMailSender javaMailSender, JdbcTemplate jdbcTemplate, Configuration configuration) {
        this.javaMailSender = javaMailSender;
        this.jdbcTemplate = jdbcTemplate;
        this.configuration = configuration;
        random = new Random();
        gson = new Gson();
        mailSubject = "TD-SATA 软研部安卓组";
    }

    /**
     * 请求发送附有验证码的邮件.
     *
     * @param useEmail 接收邮件的Email地址
     */
    @PostMapping(value = "getMailCode")
    public String getMailCode(String aesKeyStr, String verifyCiphertext, String departmentJson, String account, String useEmail) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                useEmail = server.aesDecryptData(useEmail);
                SQLTools sqlTools = new SQLTools(jdbcTemplate);
                List<Map<String, Object>> list = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        "mail", "mail_enable");
                if (list == null) {
                    return "ACCOUNT_NO_EXIST";
                }
                Map<String, Object> map = list.get(0);
                boolean equalMail = useEmail.equals(map.get("mail"));// 保存的邮件与填写的邮件一致
                if ((int) map.get("mail_enable") != 1) {// 邮件不可用
                    if (equalMail) {
                        return "MAIL_NO_VERIFY";
                    }
                    return "MAIL_ENABLE_FALSE";
                }
                if (!equalMail) {
                    return "MAIL_ENABLE_FALSE";
                }
                // 生成与保存邮件验证码
                String mailCode = String.valueOf(100000 + random.nextInt(900000));
                sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                        "temp", mailCode);
                // 10分钟后使失效
                server.invalidMail(sqlTools, department, account);
                // 发送邮件
                MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
                mimeMessageHelper.setFrom(fromEmail);
                mimeMessageHelper.setTo(useEmail);
                mimeMessageHelper.setSubject(mailSubject);
                ModelMap modelMap = new ModelMap();
                modelMap.put("verifyCode", mailCode);
                Template template = configuration.getTemplate("mail_offer_verify_code.ftl");
                mimeMessageHelper.setText(FreeMarkerTemplateUtils.processTemplateIntoString(template, modelMap), true);
                String type = "image/png";
                mimeMessageHelper.addInline("email", getStaticResource("static/mail_icon_email.png", type));
                javaMailSender.send(mimeMessage);
                return "OK";
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("发生附有验证码的邮件发生异常", e);
            return "ERROR";
        }
    }

    /**
     * 发送验证电子邮件的邮件.
     */
    @PostMapping("sendVerifyEmailMail")
    public String sendVerifyEmailMail(String aesKeyStr, String verifyCiphertext, String departmentJson, String account) {
        try {
            Server server = new Server(aesKeyStr);
            if (Tools.verifyAESKey(server, verifyCiphertext)) {
                Tools.DepartmentEnum department = gson.fromJson(server.aesDecryptData(departmentJson), Tools.DepartmentEnum.class);
                account = server.aesDecryptData(account);
                SQLTools sqlTools = new SQLTools(jdbcTemplate);
                List<Map<String, Object>> query = sqlTools.queryDBTable(department.getTableName(), "number = '" + account + "'",
                        "mail", "mail_enable", "mail_verify_time");
                if (query != null) {
                    Map<String, Object> user = query.get(0);
                    if ("1".equals(String.valueOf(user.get("mail_enable")))) {
                        return "EMAIL_ALREADY_VERIFY";
                    }
                    String email = String.valueOf(user.get("mail"));
                    if (!email.equals("null")) {
                        MimeMessage mimeMessage = javaMailSender.createMimeMessage();
                        MimeMessageHelper mimeMessageHelper = new MimeMessageHelper(mimeMessage, true);
                        mimeMessageHelper.setFrom(fromEmail);
                        mimeMessageHelper.setTo(email);
                        mimeMessageHelper.setSubject(mailSubject);
                        ModelMap modelMap = new ModelMap();
                        String link = "https://mzkt.xyz:6226/verifyEmail?number=" + account + "&v1="
                                + Tools.getKeccak512Password(department.name(), "") + "&v2="
                                + Tools.getKeccak512Password(email, "");
                        modelMap.put("link", link);
                        modelMap.put("linkText", link.substring(0, 30) + "...");
                        Template template = configuration.getTemplate("mail_verify_email.ftl");
                        String ftl = FreeMarkerTemplateUtils.processTemplateIntoString(template, modelMap);
                        mimeMessageHelper.setText(ftl, true);
                        String type = "image/png";
                        mimeMessageHelper.addInline("ourapp", getStaticResource("static/mail_icon_ourapp.png", type));
                        javaMailSender.send(mimeMessage);
                        sqlTools.updateDataForDBTable(department.getTableName(), "number = '" + account + "'",
                                "mail_verify_time", String.valueOf(System.currentTimeMillis()));
                        return "OK";
                    }
                }
            } else {
                return "AES_KEY_ERROR";
            }
        } catch (Exception e) {
            myLog.e("发送验证邮箱的邮件发生异常", e);
        }
        return "ERROR";
    }

    /**
     * 获取静态资源的DataSource对象.
     *
     * @param filePath 静态资源文件路径
     * @param type 文件对应的MIME类型
     * @return 返回静态资源的DataSource对象
     * @throws NullPointerException 不含指定路径的文件时抛出此异常
     */
    private DataSource getStaticResource(String filePath, String type) throws NullPointerException, IOException {
        InputStream inputStream = classLoader.getResourceAsStream(filePath);
        if (inputStream == null) {
            throw new NullPointerException("资源路径不存在：" + filePath);
        }
        return new ByteArrayDataSource(inputStream, type);
    }
}

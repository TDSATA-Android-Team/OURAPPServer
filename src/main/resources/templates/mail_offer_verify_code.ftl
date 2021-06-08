<!DOCTYPE html
    PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">

<head>
    <meta http-equiv="Content-Type" charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>验证码</title>
    <style>
        body {
            margin: 0;
            padding: 0;
        }
    </style>
</head>

<body>
    <table
        style="width: 800; margin: 0 auto; border-radius: 10px; margin-top: 30px; padding: 15px; box-shadow: 1px 1px 8px #f8cfa0;">
        <tbody>
            <tr>
                <td style="border: 0; text-align: center;">
                    <img src="cid:email" alt="" width="48" height="48" style="vertical-align: middle;">
                    &nbsp;
                    <span style="font-size: 18px;"> 邮箱验证</span>
                </td>
            </tr>
            <tr>
                <td style="border: 0; text-align: left; border-bottom: 1px solid rgb(207, 204, 204); padding: 10px 0;">
                    <h4>尊敬的用户，您好！</h4>
                    <p>您本次所请求的验证码为：</p>
                    <!-- 验证码入口 -->
                    <p style="color: coral;" id="code">${verifyCode}</p>
                    <p>10分钟内有效，请勿向他人泄露。</p>
                </td>
            </tr>
            <tr>
                <td style="text-align: center; font-size: 13px; color: rgb(138, 138, 138);">
                    <p>TD-SATA安卓组</p>
                </td>
            </tr>
        </tbody>
    </table>
</body>

</html>
package org.example.listener;

import jakarta.annotation.Resource;
import org.springframework.amqp.rabbit.annotation.RabbitHandler;
import org.springframework.amqp.rabbit.annotation.RabbitListener;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.mail.SimpleMailMessage;
import org.springframework.mail.javamail.JavaMailSender;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RabbitListener(queues = "mail")
public class MailQueueListener {
    @Resource
    JavaMailSender sender;

    @Value("${spring.mail.username}")
    String username;

    @RabbitHandler
    public void sendMailMessage(Map<String, Object> data) {
        String email = data.get("email").toString();
        Integer code = (Integer) data.get("code");
        String type = (String) data.get("type");
        SimpleMailMessage message = switch (type) {
            case "register" -> createMessage("欢迎注册我们的网站",
                    "您的邮件注册验证码为: " + code + " 有效时间三分钟. 为了保障您的安全, 请勿泄露验证码给他人",
                    email);
            case "reset" -> createMessage("您的密码重置邮件",
                    "你好, 您正在进行重置密码操作, 验证码: " + code + "有效时间3分钟", email);
            default -> null;
        };
        if (message == null)
            return;
        sender.send(message);
    }

    // 创建邮件
    public SimpleMailMessage createMessage(String title, String content, String email) {
        SimpleMailMessage message = new SimpleMailMessage();
        message.setSubject(title); // 主题
        message.setText(content);
        message.setTo(email);
        message.setFrom(username);
        return message;
    }
}

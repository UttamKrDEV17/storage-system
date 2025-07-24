import nodemailer from 'nodemailer';

const sendEmail = async ({to,subject,html}) => {
    const transporter = nodemailer.createTransport({
        host: process.env.SMTP_HOST,
        port: process.env.SMTP_PORT,
        secure: process.env.SMTP_SECURE === 'true', // true for 465, false for other ports
        auth: {
            user: process.env.SMTP_USER,
            pass: process.env.SMTP_PASS,
        },
    });

    await transporter.sendMail({
        from: process.env.EMAIL_USER || 'No Reply <noreply@example.com>',
        to: to,
        subject: subject,
        html: html,
    })

    console.log("email send successfully!")
}

export {sendEmail};
// src/services/emailService.js
// Email service template for user notifications
// You can integrate this with your preferred email service (SendGrid, Mailgun, AWS SES, etc.)

// Email templates for different notification types
const EMAIL_TEMPLATES = {
  user_approved: {
    subject: "[OK] Account Approved - Welcome to JARVIS AI Security!",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #3b82f6 0%, #06b6d4 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">[OK] Account Approved!</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Hello ${
            data.userName
          }!</h2>
          <p style="color: #475569; line-height: 1.6;">
            Great news! Your account has been approved and you now have full access to the JARVIS AI Security platform.
          </p>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <strong>Approval Details:</strong><br>
            <span style="color: #64748b;">Approved by: ${
              data.approvedBy
            }</span><br>
            <span style="color: #64748b;">Date: ${new Date(
              data.approvedAt
            ).toLocaleDateString()}</span>
          </div>
          
          <a href="${process.env.REACT_APP_BASE_URL}/dashboard" 
             style="display: inline-block; background: #3b82f6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px;">
            Access Dashboard
          </a>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          Welcome to JARVIS AI Security - Your intelligent security partner
        </p>
      </div>
    `,
  },

  user_rejected: {
    subject: "[X] Account Application Status - JARVIS AI Security",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #ef4444 0%, #dc2626 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Account Application Update</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Hello ${
            data.userName
          },</h2>
          <p style="color: #475569; line-height: 1.6;">
            We regret to inform you that your account application has been declined at this time.
          </p>
          
          ${
            data.rejectionReason
              ? `
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #ef4444;">
            <strong>Reason:</strong><br>
            <span style="color: #64748b;">${data.rejectionReason}</span>
          </div>
          `
              : ""
          }
          
          <p style="color: #475569; line-height: 1.6;">
            If you believe this was an error or would like to discuss your application, please contact our support team.
          </p>
          
          <a href="mailto:support@jarvisai.com" 
             style="display: inline-block; background: #6b7280; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px;">
            Contact Support
          </a>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          Thank you for your interest in JARVIS AI Security
        </p>
      </div>
    `,
  },

  user_reset_to_pending: {
    subject: " Account Status Updated - JARVIS AI Security",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #f59e0b 0%, #d97706 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Account Status Update</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Hello ${
            data.userName
          },</h2>
          <p style="color: #475569; line-height: 1.6;">
            Your account status has been reset to pending review. An administrator will review your account again shortly.
          </p>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <strong>Reset Details:</strong><br>
            <span style="color: #64748b;">Reset by: ${data.resetBy}</span><br>
            <span style="color: #64748b;">Date: ${new Date(
              data.resetAt
            ).toLocaleDateString()}</span>
          </div>
          
          <p style="color: #475569; line-height: 1.6;">
            You will receive another notification once your account has been reviewed.
          </p>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          JARVIS AI Security - Your intelligent security partner
        </p>
      </div>
    `,
  },

  promoted_to_admin: {
    subject: "[LAUNCH] Admin Access Granted - JARVIS AI Security",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #8b5cf6 0%, #7c3aed 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">[OK] Admin Access Granted!</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Congratulations ${
            data.userName
          }!</h2>
          <p style="color: #475569; line-height: 1.6;">
            You have been promoted to Administrator role on the JARVIS AI Security platform. You now have access to advanced administrative features.
          </p>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <strong>Admin Privileges Include:</strong><br>
            <ul style="color: #64748b; margin: 10px 0; padding-left: 20px;">
              <li>User approval and management</li>
              <li>System configuration access</li>
              <li>Advanced reporting features</li>
              <li>Security monitoring tools</li>
            </ul>
          </div>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <strong>Promotion Details:</strong><br>
            <span style="color: #64748b;">Promoted by: ${
              data.promotedBy
            }</span><br>
            <span style="color: #64748b;">Date: ${new Date(
              data.promotedAt
            ).toLocaleDateString()}</span>
          </div>
          
          <a href="${process.env.REACT_APP_BASE_URL}/admin" 
             style="display: inline-block; background: #8b5cf6; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px;">
            Access Admin Panel
          </a>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          With great power comes great responsibility - JARVIS AI Security
        </p>
      </div>
    `,
  },

  demoted_from_admin: {
    subject: " Role Updated - JARVIS AI Security",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #6b7280 0%, #4b5563 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Role Update Notification</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Hello ${data.userName},</h2>
          <p style="color: #475569; line-height: 1.6;">
            Your role has been updated from Administrator to regular User. Your access has been adjusted accordingly.
          </p>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0;">
            <strong>What this means:</strong><br>
            <ul style="color: #64748b; margin: 10px 0; padding-left: 20px;">
              <li>You still have full access to your user dashboard</li>
              <li>Administrative features are no longer available</li>
              <li>Your account remains active and approved</li>
            </ul>
          </div>
          
          <a href="${process.env.REACT_APP_BASE_URL}/dashboard" 
             style="display: inline-block; background: #6b7280; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px;">
            Access Dashboard
          </a>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          JARVIS AI Security - Your intelligent security partner
        </p>
      </div>
    `,
  },

  account_deleted: {
    subject: " Account Deletion Notice - JARVIS AI Security",
    html: (data) => `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: 0 auto; padding: 20px;">
        <div style="background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%); padding: 30px; border-radius: 12px; text-align: center; margin-bottom: 30px;">
          <h1 style="color: white; margin: 0; font-size: 28px;">Account Deletion Notice</h1>
        </div>
        
        <div style="background: #f8fafc; padding: 25px; border-radius: 8px; margin-bottom: 20px;">
          <h2 style="color: #1e293b; margin-top: 0;">Hello ${
            data.userName
          },</h2>
          <p style="color: #475569; line-height: 1.6;">
            This is to inform you that your account has been permanently deleted from the JARVIS AI Security platform.
          </p>
          
          <div style="background: white; padding: 15px; border-radius: 6px; margin: 20px 0; border-left: 4px solid #dc2626;">
            <strong>Deletion Details:</strong><br>
            <span style="color: #64748b;">Deleted by: ${
              data.deletedBy
            }</span><br>
            <span style="color: #64748b;">Date: ${new Date(
              data.deletedAt
            ).toLocaleDateString()}</span><br>
            <span style="color: #64748b;">Reason: ${data.reason}</span>
          </div>
          
          <p style="color: #475569; line-height: 1.6;">
            If you believe this was done in error, please contact our support team immediately.
          </p>
          
          <a href="mailto:support@jarvisai.com" 
             style="display: inline-block; background: #dc2626; color: white; padding: 12px 24px; text-decoration: none; border-radius: 6px; margin-top: 15px;">
            Contact Support
          </a>
        </div>
        
        <p style="color: #94a3b8; font-size: 14px; text-align: center;">
          JARVIS AI Security
        </p>
      </div>
    `,
  },
};

// Email service implementation
class EmailService {
  constructor() {
    // Initialize your email service here (SendGrid, Mailgun, AWS SES, etc.)
    // Example with SendGrid:
    // this.sgMail = require('@sendgrid/mail');
    // this.sgMail.setApiKey(process.env.SENDGRID_API_KEY);
  }

  async sendEmail(to, template, data) {
    try {
      const emailTemplate = EMAIL_TEMPLATES[template];
      if (!emailTemplate) {
        throw new Error(`Email template '${template}' not found`);
      }

      const emailData = {
        to: to,
        from: process.env.REACT_APP_FROM_EMAIL || "noreply@jarvisai.com",
        subject: emailTemplate.subject,
        html: emailTemplate.html(data),
      };

      // Example implementation with SendGrid:
      // await this.sgMail.send(emailData);

      // Example implementation with Mailgun:
      // await mailgun.messages().send({
      //   from: emailData.from,
      //   to: emailData.to,
      //   subject: emailData.subject,
      //   html: emailData.html,
      // });

      // Example implementation with AWS SES:
      // await ses.sendEmail({
      //   Source: emailData.from,
      //   Destination: { ToAddresses: [emailData.to] },
      //   Message: {
      //     Subject: { Data: emailData.subject },
      //     Body: { Html: { Data: emailData.html } }
      //   }
      // }).promise();

      // For development/testing, just log the email
      if (process.env.NODE_ENV === "development") {
        console.log("[EMAIL] Email would be sent:", {
          to: emailData.to,
          subject: emailData.subject,
          template: template,
          data: data,
        });
      }

      return { success: true };
    } catch (error) {
      console.error("Error sending email:", error);
      return { success: false, error: error.message };
    }
  }

  // Convenience methods for different notification types
  async sendApprovalEmail(to, data) {
    return this.sendEmail(to, "user_approved", data);
  }

  async sendRejectionEmail(to, data) {
    return this.sendEmail(to, "user_rejected", data);
  }

  async sendResetEmail(to, data) {
    return this.sendEmail(to, "user_reset_to_pending", data);
  }

  async sendPromotionEmail(to, data) {
    return this.sendEmail(to, "promoted_to_admin", data);
  }

  async sendDemotionEmail(to, data) {
    return this.sendEmail(to, "demoted_from_admin", data);
  }

  async sendDeletionEmail(to, data) {
    return this.sendEmail(to, "account_deleted", data);
  }
}

// Export singleton instance
export const emailService = new EmailService();

// Example usage in your UserApprovalContext:
/*
// Import the service
import { emailService } from '../services/emailService';

// Replace the sendNotificationEmail function with:
const sendNotificationEmail = async (userEmail, notificationType, additionalData = {}) => {
  try {
    let result;
    
    switch (notificationType) {
      case 'user_approved':
        result = await emailService.sendApprovalEmail(userEmail, additionalData);
        break;
      case 'user_rejected':
        result = await emailService.sendRejectionEmail(userEmail, additionalData);
        break;
      case 'user_reset_to_pending':
        result = await emailService.sendResetEmail(userEmail, additionalData);
        break;
      case 'promoted_to_admin':
        result = await emailService.sendPromotionEmail(userEmail, additionalData);
        break;
      case 'demoted_from_admin':
        result = await emailService.sendDemotionEmail(userEmail, additionalData);
        break;
      case 'account_deleted':
        result = await emailService.sendDeletionEmail(userEmail, additionalData);
        break;
      default:
        throw new Error(`Unknown notification type: ${notificationType}`);
    }
    
    return result;
  } catch (error) {
    console.error("Error sending email:", error);
    return { success: false, error: error.message };
  }
};
*/

export default EmailService;

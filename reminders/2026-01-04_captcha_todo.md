# CAPTCHA Re-implementation TODO

**Created:** January 4, 2026
**Priority:** Medium
**Status:** Pending

## Summary

CAPTCHA (reCAPTCHA) has been temporarily disabled from the Request Access / Contact Form to simplify development. It needs to be re-enabled before production deployment.

## What Was Disabled

### Frontend (`jarwisfrontend/src/components/ContactForm.jsx`)
- [ ] Uncomment `ReCAPTCHA` import from `react-google-recaptcha`
- [ ] Uncomment `captchaValue` state
- [ ] Uncomment CAPTCHA validation in `validateForm()`
- [ ] Uncomment `captchaToken` in submission data
- [ ] Uncomment `setCaptchaValue(null)` reset on success
- [ ] Uncomment the `<ReCAPTCHA>` component in JSX

### Backend (`api/routes/contact.py`)
- [ ] Uncomment reCAPTCHA verification logic in `submit_contact_form()`

## Configuration Required

Ensure these environment variables are set:
- `RECAPTCHA_SITE_KEY` (frontend)
- `RECAPTCHA_SECRET_KEY` (backend)

Current test keys are in `key.txt` - replace with production keys before going live.

## When to Re-enable

- Before launching to production
- After completing initial testing phase
- When spam becomes an issue on the contact form

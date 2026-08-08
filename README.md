# CP Times — Production Deployment Package

This package is prepared for deployment as a Node.js/Express web service.

## Recommended beginner deployment
1. Create a GitHub account.
2. Create a new repository named `cp-times`.
3. Upload the contents of this folder to the repository (not the ZIP file itself).
4. Create a Render Web Service and connect the GitHub repository.
5. Build command: `npm install`
6. Start command: `npm start`
7. After the Render URL works, add `cptimes.in` as a Custom Domain in Render.
8. Update DNS at the domain registrar using the exact records Render displays.
9. Render automatically manages TLS/HTTPS for the custom domain.

## Important
- Do NOT publish passwords, API keys, database credentials, or `.env` files to GitHub.
- The current CMS is a demo and should not be publicly exposed without authentication.
- The current article data is in memory; a production newsroom needs a database.

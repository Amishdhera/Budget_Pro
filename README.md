# BudgetPro (no Firebase)

One Node server: Express API + email/password login (bcrypt + JWT) + JSON-file storage, serving the app from `public/`.

    npm install
    cp .env.example .env     # set JWT_SECRET
    npm start                # open http://localhost:5000

Sign up, add your company and signature in Settings, create estimates, download PDFs.
Each account only sees its own data.

Deploy (Render/Railway/any Node host): start command `npm start`, set `JWT_SECRET`, and set `DATA_FILE`
to a path on a persistent disk. Without a persistent disk, data is lost on every redeploy.

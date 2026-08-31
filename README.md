# CP Times v2 — Real News Portal

This version adds Supabase Postgres database, Supabase Auth, Storage for article images, RLS authorization, secure newsroom login, article workflow, breaking news, YouTube settings, ads settings, sitemap and SEO-friendly article URLs.

## Setup order
1. Create a Supabase project.
2. Open Supabase SQL Editor and run `supabase-schema.sql`.
3. In Supabase Authentication > Users, create the first user with email/password.
4. Copy the user's UUID and run:
   `insert into public.profiles(id,full_name,role) values ('USER_UUID','CP Times Admin','admin');`
5. Copy your Supabase Project URL and publishable/anon key.
6. In Render > cp-times > Environment, add:
   `SUPABASE_URL`, `SUPABASE_ANON_KEY`, `SITE_URL=https://cptimes.in`
7. Push this package to the GitHub `cp-times` repository. Render will deploy automatically.
8. Open `https://cptimes.in/login` to enter the newsroom.

Never put a Supabase service-role key in GitHub or browser code. The publishable/anon key is protected by the RLS policies in the SQL schema.


## Reporter self-registration and approval

The reporter flow is now self-registration based. Administrators no longer need to add emails manually to `contributor_allowlist`.

Before deploying this version, run the **CP Times REPORTER SELF-REGISTRATION + ADMIN APPROVAL** migration at the bottom of `supabase-schema.sql` once in the Supabase SQL Editor.

Flow: reporter enters name/email -> OTP -> email verification -> password -> registration becomes `pending` -> admin approves in Newsroom -> a `journalist` profile is created -> reporter can log in.

The existing `contributor_allowlist` table is retained for backward compatibility and is migrated into the new registration table. Future registrations use `contributor_registrations` and require no manual database entry.

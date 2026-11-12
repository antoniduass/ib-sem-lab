CREATE TABLE IF NOT EXISTS users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login text NOT NULL,
    email text NOT NULL,
    password_salt bytea NOT NULL,
    password_iterations integer NOT NULL,
    password_hash bytea NOT NULL,
    role text NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    created_at timestamptz NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS users_login_key ON users (lower(login));
CREATE UNIQUE INDEX IF NOT EXISTS users_email_key ON users (lower(email));

CREATE TABLE IF NOT EXISTS sessions (
    token_hash bytea PRIMARY KEY,
    data jsonb NOT NULL,
    expires_at timestamptz NOT NULL
);

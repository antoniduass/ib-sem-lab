CREATE TABLE IF NOT EXISTS users (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    login text NOT NULL,
    email text NOT NULL,
    password_salt bytea NOT NULL,
    password_iterations integer NOT NULL,
    password_hash bytea NOT NULL,
    signing_public_key bytea NOT NULL,
    signing_key_encrypted bytea NOT NULL,
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

CREATE TABLE IF NOT EXISTS one_time_codes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    purpose text NOT NULL CHECK (purpose IN ('login', 'reset')),
    code_hash bytea NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz
);

CREATE TABLE IF NOT EXISTS recovery_codes (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    code_hash bytea NOT NULL,
    used_at timestamptz
);

CREATE TABLE IF NOT EXISTS messages (
    id bigint GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id bigint NOT NULL REFERENCES users (id) ON DELETE CASCADE,
    payload bytea NOT NULL,
    wrapped_key bytea,
    signature bytea NOT NULL,
    signer_public_key bytea NOT NULL,
    created_at timestamptz NOT NULL DEFAULT now()
);

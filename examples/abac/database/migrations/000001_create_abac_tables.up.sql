CREATE TABLE users
(
    id         UUID PRIMARY KEY,
    email      VARCHAR(255) NOT NULL UNIQUE,
    attributes JSONB        NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_users_roles ON users USING GIN ((attributes -> 'roles'));

CREATE TABLE roles
(
    id          UUID PRIMARY KEY,
    name        VARCHAR(255) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_hierarchy
(
    id             UUID PRIMARY KEY,
    parent_role_id UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    child_role_id  UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    created_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at     TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (parent_role_id, child_role_id),
    CHECK (parent_role_id != child_role_id)
);

CREATE TABLE actions
(
    id          UUID PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE resources
(
    id          UUID PRIMARY KEY,
    name        VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE role_permissions
(
    id          UUID PRIMARY KEY,
    role_id     UUID        NOT NULL REFERENCES roles (id) ON DELETE CASCADE,
    action_id   UUID        NOT NULL REFERENCES actions (id) ON DELETE CASCADE,
    resource_id UUID        NOT NULL REFERENCES resources (id) ON DELETE CASCADE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (role_id, action_id, resource_id)
);

CREATE TABLE role_permission_conditions
(
    permission_id   UUID         NOT NULL REFERENCES role_permissions (id) ON DELETE CASCADE,
    attribute_key   VARCHAR(100) NOT NULL,
    operator        VARCHAR(20)  NOT NULL,
    attribute_value JSONB        NOT NULL,
    created_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMPTZ  NOT NULL DEFAULT CURRENT_TIMESTAMP,

    UNIQUE (permission_id, attribute_key, operator)
);

CREATE TABLE orders
(
    id         UUID PRIMARY KEY,
    name       VARCHAR(50) NOT NULL UNIQUE,
    attributes JSONB       NOT NULL DEFAULT '{}',
    created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_orders_user_id ON orders USING BTREE ((attributes ->> 'user_id'));
CREATE INDEX idx_orders_total_amount ON orders USING BTREE (((attributes ->> 'total_amount')::numeric));
CREATE INDEX idx_orders_status ON orders USING BTREE ((attributes ->> 'status'));

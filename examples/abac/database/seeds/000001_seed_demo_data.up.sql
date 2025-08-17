-- 000001_seed_demo_data.up.sql

-- Ensure required roles exist
INSERT INTO roles (id, name, description)
VALUES
    (gen_random_uuid(), 'admin', 'Administrator role'),
    (gen_random_uuid(), 'customer_service', 'Customer service role'),
    (gen_random_uuid(), 'customer', 'Customer role')
ON CONFLICT (name) DO NOTHING;

-- Role hierarchy: admin -> customer_service -> customer
INSERT INTO role_hierarchy (id, parent_role_id, child_role_id)
SELECT gen_random_uuid(), parent.id, child.id
FROM roles parent
         JOIN roles child ON true
WHERE (parent.name = 'admin' AND child.name = 'customer_service')
   OR (parent.name = 'customer_service' AND child.name = 'customer')
ON CONFLICT (parent_role_id, child_role_id) DO NOTHING;

-- Actions and resource
INSERT INTO actions (id, name, description)
VALUES
    (gen_random_uuid(), 'create', 'Create order'),
    (gen_random_uuid(), 'read',   'Read order')
ON CONFLICT (name) DO NOTHING;

INSERT INTO resources (id, name, description)
VALUES (gen_random_uuid(), 'order', 'Order resource')
ON CONFLICT (name) DO NOTHING;

-- Role permissions
-- admin: create/read any order
INSERT INTO role_permissions (id, role_id, action_id, resource_id)
SELECT gen_random_uuid(), r.id, a.id, res.id
FROM roles r, actions a, resources res
WHERE r.name = 'admin' AND res.name = 'order' AND a.name IN ('create','read')
ON CONFLICT (role_id, action_id, resource_id) DO NOTHING;

-- customer_service: read any order
INSERT INTO role_permissions (id, role_id, action_id, resource_id)
SELECT gen_random_uuid(), r.id, a.id, res.id
FROM roles r, actions a, resources res
WHERE r.name = 'customer_service' AND res.name = 'order' AND a.name = 'read'
ON CONFLICT (role_id, action_id, resource_id) DO NOTHING;

-- customer: create/read only own order (add conditions)
INSERT INTO role_permissions (id, role_id, action_id, resource_id)
SELECT gen_random_uuid(), r.id, a.id, res.id
FROM roles r, actions a, resources res
WHERE r.name = 'customer' AND res.name = 'order' AND a.name IN ('create','read')
ON CONFLICT (role_id, action_id, resource_id) DO NOTHING;

-- Attach conditions to the customer's permissions
-- owner == ${subject.id}
INSERT INTO role_permission_conditions (permission_id, attribute_key, operator, attribute_value)
SELECT rp.id, 'owner', 'equals', '"${subject.id}"'::jsonb
FROM role_permissions rp
         JOIN roles r ON rp.role_id = r.id
         JOIN actions a ON rp.action_id = a.id
         JOIN resources res ON rp.resource_id = res.id
WHERE r.name = 'customer' AND res.name = 'order' AND a.name IN ('create','read')
ON CONFLICT (permission_id, attribute_key, operator) DO NOTHING;

-- Demo users
INSERT INTO users (id, email, attributes)
VALUES
    (gen_random_uuid(), 'alice@abac.com', '{"roles":["admin"],"department":"operations","region":"global"}'),
    (gen_random_uuid(), 'bob@abac.com',   '{"roles":["customer_service"],"department":"support","region":"na"}'),
    (gen_random_uuid(), 'cara@abac.com',  '{"roles":["customer"],"department":"consumer","region":"eu"}')
ON CONFLICT (email) DO NOTHING;

-- Demo orders (owned by cara)
INSERT INTO role_permission_conditions (permission_id, attribute_key, operator, attribute_value)
SELECT rp.id, 'owner', 'equals', '"${subject.id}"'::jsonb
FROM role_permissions rp
         JOIN roles r ON rp.role_id = r.id
         JOIN actions a ON rp.action_id = a.id
         JOIN resources res ON rp.resource_id = res.id
WHERE r.name = 'customer' AND res.name = 'order' AND a.name IN ('create','read')
ON CONFLICT (permission_id, attribute_key, operator) DO NOTHING;

-- Demo users
INSERT INTO users (id, email, attributes)
VALUES
    (gen_random_uuid(), 'alice@abac.com', '{"roles":["admin"],"department":"operations","region":"global"}'),
    (gen_random_uuid(), 'bob@abac.com',   '{"roles":["customer_service"],"department":"support","region":"na"}'),
    (gen_random_uuid(), 'cara@abac.com',  '{"roles":["customer"],"department":"consumer","region":"eu"}')
ON CONFLICT (email) DO NOTHING;

-- Demo orders (owned by cara - owner is user ID)
INSERT INTO orders (id, name, attributes)
VALUES
    (gen_random_uuid(), 'order-001', jsonb_build_object(
            'owner', (SELECT id FROM users WHERE email = 'bob@abac.com'),
            'total_amount', '123.45',
            'status', 'created'
                                     )),
    (gen_random_uuid(), 'order-002', jsonb_build_object(
            'owner', (SELECT id FROM users WHERE email = 'cara@abac.com'),
            'total_amount', '42.00',
            'status', 'created'
                                     ))
ON CONFLICT (name) DO NOTHING;

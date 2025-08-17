-- 000001_seed_demo_data.down.sql

-- Remove demo orders
DELETE
FROM orders
WHERE name IN ('order-001', 'order-002');

-- Remove demo users
DELETE
FROM users
WHERE email IN ('alice@abac.com', 'bob@abac.com', 'cara@abac.com');

-- Remove customer conditions on order permissions
WITH cust_perms AS (SELECT rp.id
                    FROM role_permissions rp
                             JOIN roles r ON rp.role_id = r.id
                             JOIN actions a ON rp.action_id = a.id
                             JOIN resources res ON rp.resource_id = res.id
                    WHERE r.name = 'customer'
                      AND res.name = 'order'
                      AND a.name IN ('create', 'read'))
DELETE
FROM role_permission_conditions rpc
    USING cust_perms cp
WHERE rpc.permission_id = cp.id
  AND rpc.attribute_key = 'owner'
  AND rpc.operator = 'equals';

-- Remove role_permissions inserted for demo (admin, customer_service, customer on order)
DELETE
FROM role_permissions rp
    USING roles r, actions a, resources res
WHERE rp.role_id = r.id
  AND rp.action_id = a.id
  AND rp.resource_id = res.id
  AND res.name = 'order'
  AND r.name IN ('admin', 'customer_service', 'customer')
  AND a.name IN ('create', 'read');

-- Remove role hierarchy links for demo
DELETE
FROM role_hierarchy rh
    USING roles parent, roles child
WHERE rh.parent_role_id = parent.id
  AND rh.child_role_id = child.id
  AND (
    (parent.name = 'admin' AND child.name = 'customer_service') OR
    (parent.name = 'customer_service' AND child.name = 'customer')
    );

-- Remove demo roles (safe even if used elsewhere because we removed dependent rows)
DELETE
FROM roles
WHERE name IN ('admin', 'customer_service', 'customer');

-- Optionally remove actions and resource if they were created for demo
DELETE
FROM role_permissions rp
WHERE NOT EXISTS (SELECT 1 FROM roles r WHERE r.id = rp.role_id); -- safety cleanup

DELETE
FROM actions
WHERE name IN ('create', 'read');
DELETE
FROM resources
WHERE name = 'order';
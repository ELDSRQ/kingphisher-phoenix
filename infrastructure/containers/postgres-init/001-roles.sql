-- Local dev bootstrap for the Kingphisher-Phoenix stack.
-- Creates the INSERT-only audit role and the test database used by pytest.
-- Production grants live in infrastructure/terraform; this is disposable-local only.

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'audit_writer') THEN
    CREATE ROLE audit_writer LOGIN PASSWORD 'audit_writer';
  END IF;
END
$$;

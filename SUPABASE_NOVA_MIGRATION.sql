-- ═══════════════════════════════════════════════════════════════
-- AegisForge v2.0 — Project Nova Database Architecture
-- Run in Supabase Dashboard → SQL Editor → New Query → Run.
--
-- MIGRATION STRATEGY: All original tables preserved.
-- New tables added alongside. Zero data loss.
-- ═══════════════════════════════════════════════════════════════

-- ── ORIGINAL TABLES (PRESERVED) ──────────────
-- waitlist          → still active for early access
-- preview_requests  → still active for analytics
-- scan_reports      → still active for scanner
-- ai_blueprints     → still active for AI blueprints

-- ══════════════════════════════════════════════
-- 1. USERS
-- ══════════════════════════════════════════════
create table if not exists public.users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    name text,
    avatar_url text,
    role text not null default 'user',           -- user, admin, beta
    company text,
    country text,
    subscription text not null default 'free',    -- free, pro, business
    subscription_id text,                         -- Stripe subscription ID
    created_at timestamptz not null default now(),
    last_active_at timestamptz not null default now(),
    metadata jsonb default '{}'
);

create index if not exists users_email_idx on public.users (email);
create index if not exists users_subscription_idx on public.users (subscription);
alter table public.users enable row level security;

-- ══════════════════════════════════════════════
-- 2. PROJECTS
-- ══════════════════════════════════════════════
create table if not exists public.projects (
    id uuid primary key default gen_random_uuid(),
    owner_id uuid not null references public.users (id) on delete cascade,
    name text not null,
    description text,
    status text not null default 'active',        -- active, archived, building, deployed
    tech_stack jsonb default '[]',
    framework text,
    blueprint_id uuid,                            -- references blueprints
    nova_context jsonb default '{}',              -- Nova's understanding of the project
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists projects_owner_idx on public.projects (owner_id);
create index if not exists projects_status_idx on public.projects (status);
create index if not exists projects_updated_idx on public.projects (updated_at desc);
alter table public.projects enable row level security;

-- ══════════════════════════════════════════════
-- 3. NOVA MEMORY
-- ══════════════════════════════════════════════
create table if not exists public.nova_memory (
    id uuid primary key default gen_random_uuid(),
    user_id uuid not null references public.users (id) on delete cascade,
    project_id uuid references public.projects (id) on delete cascade,
    conversation_history jsonb default '[]',
    decisions jsonb default '[]',
    previous_prompts jsonb default '[]',
    architecture_choices jsonb default '{}',
    preferred_stack jsonb default '{}',
    ai_notes text,
    project_context jsonb default '{}',
    user_preferences jsonb default '{}',
    created_at timestamptz not null default now(),
    updated_at timestamptz not null default now()
);

create index if not exists nova_memory_user_idx on public.nova_memory (user_id);
create index if not exists nova_memory_project_idx on public.nova_memory (project_id);
alter table public.nova_memory enable row level security;

-- ══════════════════════════════════════════════
-- 4. SECURITY REPORTS (enriched scan_reports)
-- ══════════════════════════════════════════════
create table if not exists public.security_reports (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references public.users (id) on delete set null,
    project_id uuid references public.projects (id) on delete set null,
    report_id text not null unique,
    url text not null,
    domain text not null,
    score integer,
    grade text,
    risk_level text,                              -- low, medium, high, critical
    confidence text,                              -- high, medium, low
    findings jsonb default '{}',
    recommendations jsonb default '[]',
    checks_summary jsonb default '{}',
    full_report jsonb,
    scan_duration_seconds real,
    previous_report_id text,                      -- for comparison
    export_urls jsonb default '{}',
    created_at timestamptz not null default now()
);

create index if not exists security_reports_report_id_idx on public.security_reports (report_id);
create index if not exists security_reports_user_idx on public.security_reports (user_id);
create index if not exists security_reports_domain_idx on public.security_reports (domain);
create index if not exists security_reports_created_idx on public.security_reports (created_at desc);
alter table public.security_reports enable row level security;

-- ══════════════════════════════════════════════
-- 5. BLUEPRINTS (enriched ai_blueprints)
-- ══════════════════════════════════════════════
create table if not exists public.blueprints (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references public.users (id) on delete set null,
    project_id uuid references public.projects (id) on delete set null,
    idea text not null,
    audience text,
    platform text,
    budget text,
    architecture jsonb default '{}',
    features jsonb default '[]',
    roles jsonb default '[]',
    database_schema jsonb default '[]',
    api_endpoints jsonb default '[]',
    ui_plan jsonb default '[]',
    timeline jsonb default '[]',
    security_plan jsonb default '[]',
    full_output jsonb not null default '{}',
    model text,
    provider text,
    created_at timestamptz not null default now()
);

create index if not exists blueprints_user_idx on public.blueprints (user_id);
create index if not exists blueprints_project_idx on public.blueprints (project_id);
create index if not exists blueprints_idea_idx on public.blueprints (idea);
create index if not exists blueprints_created_idx on public.blueprints (created_at desc);
alter table public.blueprints enable row level security;

-- ══════════════════════════════════════════════
-- 6. DEPLOYMENTS
-- ══════════════════════════════════════════════
create table if not exists public.deployments (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references public.projects (id) on delete cascade,
    user_id uuid not null references public.users (id) on delete cascade,
    platform text not null,                        -- vercel, render, aws, gcp, custom
    url text,
    build_status text not null default 'pending', -- pending, building, deployed, failed
    deployment_logs text,
    git_commit text,
    git_branch text default 'main',
    rollback_url text,
    metadata jsonb default '{}',
    deployed_at timestamptz,
    created_at timestamptz not null default now()
);

create index if not exists deployments_project_idx on public.deployments (project_id);
create index if not exists deployments_user_idx on public.deployments (user_id);
create index if not exists deployments_status_idx on public.deployments (build_status);
alter table public.deployments enable row level security;

-- ══════════════════════════════════════════════
-- 7. REPOSITORIES
-- ══════════════════════════════════════════════
create table if not exists public.repositories (
    id uuid primary key default gen_random_uuid(),
    project_id uuid not null references public.projects (id) on delete cascade,
    user_id uuid not null references public.users (id) on delete cascade,
    github_repo text not null,
    branch text default 'main',
    last_commit text,
    last_commit_at timestamptz,
    languages jsonb default '[]',
    framework text,
    dependencies jsonb default '{}',
    metadata jsonb default '{}',
    created_at timestamptz not null default now()
);

create index if not exists repositories_project_idx on public.repositories (project_id);
create index if not exists repositories_user_idx on public.repositories (user_id);
alter table public.repositories enable row level security;

-- ══════════════════════════════════════════════
-- 8. NOVA ACTIONS (audit log)
-- ══════════════════════════════════════════════
create table if not exists public.nova_actions (
    id uuid primary key default gen_random_uuid(),
    user_id uuid references public.users (id) on delete set null,
    project_id uuid references public.projects (id) on delete set null,
    agent text not null,                           -- product, builder, security, deploy, growth
    action text not null,
    input jsonb default '{}',
    output jsonb default '{}',
    duration_ms integer,
    model text,
    provider text,
    success boolean default true,
    error text,
    created_at timestamptz not null default now()
);

create index if not exists nova_actions_user_idx on public.nova_actions (user_id);
create index if not exists nova_actions_project_idx on public.nova_actions (project_id);
create index if not exists nova_actions_agent_idx on public.nova_actions (agent);
create index if not exists nova_actions_created_idx on public.nova_actions (created_at desc);
alter table public.nova_actions enable row level security;

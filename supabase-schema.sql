create extension if not exists pgcrypto;
create table if not exists public.profiles(id uuid primary key references auth.users(id) on delete cascade,full_name text,role text not null default 'journalist' check(role in('journalist','editor','admin')),created_at timestamptz default now());
create table if not exists public.articles(id uuid primary key default gen_random_uuid(),title text not null,slug text unique not null,category text not null,excerpt text,body text not null,image_url text,author_name text not null default 'CP Times Desk',status text not null default 'draft' check(status in('draft','review','published','archived')),featured boolean default false,published_at timestamptz,created_by uuid references public.profiles(id),updated_by uuid references public.profiles(id),created_at timestamptz default now(),updated_at timestamptz default now());
create table if not exists public.breaking_news(id uuid primary key default gen_random_uuid(),headline text not null,url text,active boolean default true,priority integer default 0,created_by uuid references public.profiles(id),created_at timestamptz default now());
create table if not exists public.site_settings(key text primary key,value text);
insert into public.site_settings(key,value) values('youtube_channel_url',''),('youtube_featured_video',''),('primary_ad_code',''),('newsletter_embed','') on conflict(key) do nothing;
create or replace function public.is_staff() returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from profiles where id=auth.uid() and role in('journalist','editor','admin'));$$;
create or replace function public.is_editor() returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from profiles where id=auth.uid() and role in('editor','admin'));$$;
create or replace function public.is_admin() returns boolean language sql stable security definer set search_path=public as $$select exists(select 1 from profiles where id=auth.uid() and role='admin');$$;
alter table public.profiles enable row level security; alter table public.articles enable row level security; alter table public.breaking_news enable row level security; alter table public.site_settings enable row level security;
create policy "public published" on public.articles for select using(status='published');
create policy "staff read" on public.articles for select to authenticated using(public.is_staff());
create policy "staff insert" on public.articles for insert to authenticated
with check(public.is_staff() and (status <> 'published' or public.is_editor()));
create policy "staff update" on public.articles for update to authenticated
using(public.is_staff())
with check(public.is_staff() and (status <> 'published' or public.is_editor()));
create policy "editor delete" on public.articles for delete to authenticated using(public.is_editor());
create policy "public breaking" on public.breaking_news for select using(active=true);
create policy "staff breaking" on public.breaking_news for all to authenticated using(public.is_staff()) with check(public.is_staff());
create policy "public settings" on public.site_settings for select using(true);
create policy "admin settings" on public.site_settings for all to authenticated using(public.is_admin()) with check(public.is_admin());
create policy "own profile" on public.profiles for select to authenticated using(id=auth.uid());
insert into storage.buckets(id,name,public) values('article-images','article-images',true) on conflict(id) do update set public=true;
create policy "public image read" on storage.objects for select using(bucket_id='article-images');
create policy "staff image upload" on storage.objects for insert to authenticated with check(bucket_id='article-images' and public.is_staff());
create policy "staff image update" on storage.objects for update to authenticated using(bucket_id='article-images' and public.is_staff()) with check(bucket_id='article-images' and public.is_staff());
create policy "staff image delete" on storage.objects for delete to authenticated using(bucket_id='article-images' and public.is_staff());
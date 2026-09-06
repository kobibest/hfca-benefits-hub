-- כניסה לאתר בתעודת זהות — אימות מול רשימת החברים
-- שים לב: הועלה לפרויקט HFCA (ref ekpkmqczjplamtadvqgv) — מערכת ההתאחדות,
-- ולא לפרויקט של אתר ההטבות. שם חיה טבלת advisors.

-- חלק מהמספרים נשמרו בלי האפס המוביל (1,296 מתוך 3,059 הם 8 ספרות),
-- ולכן שני הצדדים מנורמלים: ספרות בלבד, מרופד באפסים ל-9.
create index if not exists advisors_id_number_norm_idx
  on public.advisors (lpad(regexp_replace(id_number, '\D', '', 'g'), 9, '0'));

-- מגבלת קצב לנקודת הקצה הפתוחה, כדי שלא יהיה אפשר לסרוק את מרחב תעודות הזהות.
create table if not exists public.benefits_hub_login_attempts(
  id           bigserial primary key,
  ip           text,
  succeeded    boolean not null default false,
  attempted_at timestamptz not null default now()
);
comment on table public.benefits_hub_login_attempts is
  'Rate-limiting trail for benefits_hub_verify_member. Rows older than a day are pruned by the function.';
create index if not exists benefits_hub_login_attempts_ip_time_idx
  on public.benefits_hub_login_attempts (ip, attempted_at desc) where not succeeded;

alter table public.benefits_hub_login_attempts enable row level security;
drop policy if exists benefits_hub_login_attempts_admin_read on public.benefits_hub_login_attempts;
create policy benefits_hub_login_attempts_admin_read
  on public.benefits_hub_login_attempts for select to authenticated using (true);

-- אתר ההטבות יושב בפרויקט Supabase אחר ואינו מחזיק מפתח לפרויקט הזה. הקריאה
-- מגיעה דרך Edge Function ציבורית (verify-member) שרצה כאן עם service role,
-- ולכן כתובת המבקר מועברת במפורש — הכותרת בשלב הזה כבר שייכת לפונקציה.
create or replace function public.benefits_hub_verify_member(p_id text, p_ip text default null)
returns json
language plpgsql
security definer
set search_path = public, pg_temp
as $$
declare
  v_norm  text;
  v_ip    text;
  v_fails integer;
  v_name  text;
  v_first text;
  v_hit   boolean;
begin
  v_norm := regexp_replace(coalesce(p_id, ''), '\D', '', 'g');
  if length(v_norm) not between 5 and 9 then
    return json_build_object('ok', false, 'reason', 'invalid');
  end if;
  v_norm := lpad(v_norm, 9, '0');

  v_ip := nullif(btrim(coalesce(p_ip, split_part(coalesce(
            nullif(current_setting('request.headers', true), '')::json ->> 'x-forwarded-for', ''), ',', 1))), '');

  if v_ip is not null then
    select count(*) into v_fails
      from public.benefits_hub_login_attempts
     where ip = v_ip and not succeeded and attempted_at > now() - interval '1 hour';
    if v_fails >= 30 then
      return json_build_object('ok', false, 'reason', 'rate_limited');
    end if;
  end if;

  select a.full_name, a.first_name
    into v_name, v_first
    from public.advisors a
   where a.status = 'active_member'
     and length(regexp_replace(a.id_number, '\D', '', 'g')) between 5 and 9
     and lpad(regexp_replace(a.id_number, '\D', '', 'g'), 9, '0') = v_norm
   limit 1;
  v_hit := found;

  insert into public.benefits_hub_login_attempts(ip, succeeded) values (v_ip, v_hit);
  if random() < 0.01 then
    delete from public.benefits_hub_login_attempts where attempted_at < now() - interval '1 day';
  end if;

  if not v_hit then
    return json_build_object('ok', false, 'reason', 'not_found');
  end if;
  return json_build_object('ok', true,
                           'name', coalesce(nullif(btrim(v_first), ''), nullif(btrim(v_name), '')));
end;
$$;

comment on function public.benefits_hub_verify_member(text, text) is
  'Benefits Hub gate: returns {ok,name} for an active_member national ID. Called by the verify-member Edge Function; never exposes advisor rows.';

-- רק ה-Edge Function (service role) רשאית לקרוא — שום דפדפן לא מגיע לפרויקט הזה.
drop function if exists public.benefits_hub_verify_member(text);
revoke all on function public.benefits_hub_verify_member(text, text) from public, anon, authenticated;
grant execute on function public.benefits_hub_verify_member(text, text) to service_role;

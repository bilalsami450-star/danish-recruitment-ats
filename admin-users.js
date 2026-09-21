const { createClient } = require('@supabase/supabase-js');

const URL = process.env.SUPABASE_URL;
const SECRET = process.env.SUPABASE_SECRET_KEY;
const PUBLISHABLE = process.env.SUPABASE_PUBLISHABLE_KEY;

function client(key) {
  return createClient(URL, key, {
    auth: { autoRefreshToken: false, persistSession: false, detectSessionInUrl: false }
  });
}

async function requireAdmin(req) {
  if (!URL || !SECRET || !PUBLISHABLE) throw Object.assign(new Error('Server configuration incomplete'), { status: 500 });
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : '';
  if (!token) throw Object.assign(new Error('Missing session'), { status: 401 });

  const publicClient = client(PUBLISHABLE);
  const { data: userData, error: userError } = await publicClient.auth.getUser(token);
  if (userError || !userData?.user) throw Object.assign(new Error('Invalid session'), { status: 401 });

  const admin = client(SECRET);
  const { data: profile, error: profileError } = await admin
    .from('profiles').select('role').eq('id', userData.user.id).single();
  if (profileError || profile?.role !== 'admin') throw Object.assign(new Error('Admin access required'), { status: 403 });
  return { admin, user: userData.user };
}

module.exports = async function handler(req, res) {
  res.setHeader('Cache-Control', 'no-store');
  try {
    const { admin, user } = await requireAdmin(req);

    if (req.method === 'GET') {
      const { data, error } = await admin.auth.admin.listUsers({ page: 1, perPage: 200 });
      if (error) throw error;
      const { data: profiles, error: pError } = await admin.from('profiles').select('id,full_name,email,role,created_at');
      if (pError) throw pError;
      const byId = Object.fromEntries((profiles || []).map(p => [p.id, p]));
      const users = (data.users || []).map(u => ({
        id: u.id,
        email: u.email,
        created_at: u.created_at,
        last_sign_in_at: u.last_sign_in_at,
        confirmed_at: u.confirmed_at,
        full_name: byId[u.id]?.full_name || u.user_metadata?.full_name || '',
        role: byId[u.id]?.role || 'viewer'
      }));
      return res.status(200).json({ users, currentUserId: user.id });
    }

    if (req.method === 'POST') {
      const { email, role = 'viewer', fullName = '', redirectTo } = req.body || {};
      if (!email || !['viewer','editor'].includes(role)) return res.status(400).json({ error: 'Valid email and role are required.' });
      const options = { data: { full_name: fullName } };
      if (redirectTo) options.redirectTo = redirectTo;
      const { data, error } = await admin.auth.admin.inviteUserByEmail(email, options);
      if (error) throw error;
      const invited = data?.user;
      if (invited?.id) {
        const { error: upsertError } = await admin.from('profiles').upsert({
          id: invited.id,
          full_name: fullName,
          email,
          role
        }, { onConflict: 'id' });
        if (upsertError) throw upsertError;
      }
      return res.status(200).json({ ok: true, user: invited });
    }

    if (req.method === 'PATCH') {
      const { id, role, fullName } = req.body || {};
      if (!id || !['viewer','editor','admin'].includes(role)) return res.status(400).json({ error: 'Valid user id and role are required.' });
      const updates = { role };
      if (typeof fullName === 'string') updates.full_name = fullName;
      const { error } = await admin.from('profiles').update(updates).eq('id', id);
      if (error) throw error;
      return res.status(200).json({ ok: true });
    }

    if (req.method === 'DELETE') {
      const id = req.query.id;
      if (!id) return res.status(400).json({ error: 'User id is required.' });
      if (id === user.id) return res.status(400).json({ error: 'You cannot revoke your own admin account.' });
      const { error } = await admin.auth.admin.deleteUser(id);
      if (error) throw error;
      return res.status(200).json({ ok: true });
    }

    res.setHeader('Allow', 'GET, POST, PATCH, DELETE');
    return res.status(405).json({ error: 'Method not allowed' });
  } catch (err) {
    return res.status(err.status || 500).json({ error: err.message || 'Server error' });
  }
};

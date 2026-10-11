import express from 'express';
import cors from 'cors';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import multer from 'multer';
import path from 'path';
import { fileURLToPath } from 'url';
import 'dotenv/config';
import { pool as db } from './db.js';

const dir = path.dirname(fileURLToPath(import.meta.url));
const app = express();
app.use(cors(), express.json());
app.use('/uploads', express.static(path.join(dir, 'uploads')));
app.use(express.static(path.join(dir, 'public')));

const up = multer({ storage: multer.diskStorage({
  destination: path.join(dir, 'uploads'),
  filename: (q, f, cb) => cb(null, Date.now() + path.extname(f.originalname)) }) });
const q = async (sql, p = []) => (await db.query(sql, p))[0];
const notify = (uid, msg) => q('INSERT INTO notifications (user_id,message) VALUES (?,?)', [uid, msg]);
const notifyFinance = async (msg) => { for (const f of await q("SELECT id FROM users WHERE role IN ('finance','admin')")) await notify(f.id, msg); };
const wrap = (fn) => (req, res) => fn(req, res).catch((e) => { console.error(e); res.status(500).json({ message: e.message }); });
const auth = (roles = []) => (req, res, next) => {
  try {
    const u = jwt.verify((req.headers.authorization || '').slice(7), process.env.JWT_SECRET);
    if (roles.length && !roles.includes(u.role)) return res.status(403).json({ message: 'You do not have access to this' });
    req.user = u; next();
  } catch { res.status(401).json({ message: 'Please sign in again' }); }
};

// ---------- Auth ----------
app.post('/api/login', wrap(async (req, res) => {
  const [u] = await q('SELECT * FROM users WHERE email=? AND is_active=1', [req.body.email]);
  if (!u || !(await bcrypt.compare(req.body.password || '', u.password_hash)))
    return res.status(401).json({ message: 'Invalid email or password' });
  const token = jwt.sign({ id: u.id, role: u.role, name: u.name }, process.env.JWT_SECRET, { expiresIn: '8h' });
  res.json({ token, user: { id: u.id, name: u.name, role: u.role } });
}));

app.get('/api/categories', auth(), wrap(async (req, res) => res.json(await q('SELECT * FROM categories'))));

// ---------- Expenses ----------
app.get('/api/expenses', auth(), wrap(async (req, res) => res.json(await q(
  'SELECT e.*,c.name category FROM expenses e JOIN categories c ON c.id=e.category_id WHERE e.user_id=? ORDER BY e.expense_date DESC,e.id DESC', [req.user.id]))));

app.post('/api/expenses', auth(), up.single('receipt'), wrap(async (req, res) => {
  const b = req.body, receipt = req.file?.filename || null;
  const [c] = await q('SELECT * FROM categories WHERE id=?', [b.category_id]);
  const flag = (c.daily_limit && +b.amount > +c.daily_limit) || (c.receipt_required && !receipt) ? 1 : 0;
  await q('INSERT INTO expenses (user_id,category_id,expense_date,merchant,amount,payment_mode,description,receipt_path,policy_flag) VALUES (?,?,?,?,?,?,?,?,?)',
    [req.user.id, b.category_id, b.expense_date, b.merchant, b.amount, b.payment_mode, b.description, receipt, flag]);
  res.json({ ok: 1, policy_flag: flag });
}));

app.delete('/api/expenses/:id', auth(), wrap(async (req, res) => {
  await q('DELETE FROM expenses WHERE id=? AND user_id=? AND report_id IS NULL', [req.params.id, req.user.id]);
  res.json({ ok: 1 });
}));

// ---------- Reports ----------
app.get('/api/reports', auth(), wrap(async (req, res) => res.json(await q(
  'SELECT r.*,u.name employee FROM reports r JOIN users u ON u.id=r.user_id WHERE r.user_id=? ORDER BY r.id DESC', [req.user.id]))));

app.post('/api/reports', auth(), wrap(async (req, res) => {
  const { title, purpose, expense_ids = [] } = req.body;
  if (!title || !expense_ids.length) return res.status(400).json({ message: 'Enter a title and select at least one expense' });
  const ph = expense_ids.map(() => '?').join(',');
  const rows = await q(`SELECT amount FROM expenses WHERE user_id=? AND report_id IS NULL AND id IN (${ph})`, [req.user.id, ...expense_ids]);
  const total = rows.reduce((s, e) => s + +e.amount, 0);
  const r = await q('INSERT INTO reports (user_id,title,purpose,total_amount) VALUES (?,?,?,?)', [req.user.id, title, purpose, total]);
  await q(`UPDATE expenses SET report_id=? WHERE user_id=? AND report_id IS NULL AND id IN (${ph})`, [r.insertId, req.user.id, ...expense_ids]);
  res.json({ id: r.insertId });
}));

app.get('/api/reports/:id', auth(), wrap(async (req, res) => {
  const [r] = await q('SELECT r.*,u.name employee FROM reports r JOIN users u ON u.id=r.user_id WHERE r.id=?', [req.params.id]);
  if (!r || (r.user_id !== req.user.id && req.user.role === 'employee')) return res.status(404).json({ message: 'Report not found' });
  res.json({ ...r,
    expenses: await q('SELECT e.*,c.name category FROM expenses e JOIN categories c ON c.id=e.category_id WHERE report_id=?', [r.id]),
    approvals: await q('SELECT a.*,u.name approver FROM approvals a JOIN users u ON u.id=a.approver_id WHERE report_id=? ORDER BY a.id', [r.id]) });
}));

app.post('/api/reports/:id/submit', auth(), wrap(async (req, res) => {
  const [r] = await q("SELECT * FROM reports WHERE id=? AND user_id=? AND status IN ('draft','rejected')", [req.params.id, req.user.id]);
  if (!r) return res.status(400).json({ message: 'This report cannot be submitted' });
  await q("UPDATE reports SET status='submitted',submitted_at=NOW() WHERE id=?", [r.id]);
  const [me] = await q('SELECT manager_id FROM users WHERE id=?', [req.user.id]);
  const msg = `${req.user.name} submitted "${r.title}" for approval`;
  me.manager_id ? await notify(me.manager_id, msg) : await notifyFinance(msg);
  res.json({ ok: 1 });
}));

// ---------- Approvals ----------
app.get('/api/approvals', auth(['manager', 'finance', 'admin']), wrap(async (req, res) => {
  const fin = req.user.role !== 'manager';
  const where = fin ? "(r.status IN ('manager_approved','approved') OR (r.status='submitted' AND u.manager_id IS NULL))" : "r.status='submitted' AND u.manager_id=?";
  res.json(await q(`SELECT r.*,u.name employee FROM reports r JOIN users u ON u.id=r.user_id WHERE ${where} ORDER BY r.id DESC`, fin ? [] : [req.user.id]));
}));

app.post('/api/approvals/:id', auth(['manager', 'finance', 'admin']), wrap(async (req, res) => {
  const { decision, comment } = req.body, mgr = req.user.role === 'manager';
  const [r] = await q('SELECT r.*,u.manager_id FROM reports r JOIN users u ON u.id=r.user_id WHERE r.id=?', [req.params.id]);
  if (!r) return res.status(404).json({ message: 'Report not found' });
  if (mgr && (r.status !== 'submitted' || r.manager_id !== req.user.id)) return res.status(403).json({ message: 'This report is not assigned to you' });
  if (!mgr && !['submitted', 'manager_approved'].includes(r.status)) return res.status(400).json({ message: 'This report is not waiting for approval' });
  const st = decision === 'rejected' ? 'rejected' : mgr ? 'manager_approved' : 'approved';
  await q('UPDATE reports SET status=? WHERE id=?', [st, r.id]);
  await q('INSERT INTO approvals (report_id,approver_id,level,decision,comment,decided_at) VALUES (?,?,?,?,?,NOW())', [r.id, req.user.id, mgr ? 1 : 2, decision, comment || null]);
  await notify(r.user_id, `Your report "${r.title}" was ${decision} by ${req.user.name}`);
  if (st === 'manager_approved') await notifyFinance(`Report "${r.title}" is waiting for final approval`);
  res.json({ ok: 1 });
}));

app.post('/api/reimburse/:id', auth(['finance', 'admin']), wrap(async (req, res) => {
  const [r] = await q("SELECT * FROM reports WHERE id=? AND status='approved'", [req.params.id]);
  if (!r) return res.status(400).json({ message: 'Only approved reports can be reimbursed' });
  await q('INSERT INTO reimbursements (report_id,paid_amount,paid_on,reference_no) VALUES (?,?,CURDATE(),?)', [r.id, r.total_amount, req.body.reference || '']);
  await q("UPDATE reports SET status='reimbursed' WHERE id=?", [r.id]);
  await notify(r.user_id, `Report "${r.title}" has been reimbursed`);
  res.json({ ok: 1 });
}));

// ---------- Dashboard, notifications ----------
app.get('/api/dashboard', auth(), wrap(async (req, res) => {
  const all = ['finance', 'admin'].includes(req.user.role);
  res.json(await q(all ? 'SELECT * FROM expenses' : 'SELECT * FROM expenses WHERE user_id=?', all ? [] : [req.user.id]));
}));

// ---------- Production Server Listening Logic ----------
const PORT = process.env.PORT || 5000;
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server successfully up and listening on port ${PORT}`);
});

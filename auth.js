// auth.js
function requireAdmin(req, res, next) {
  if (req.session && req.session.user && req.session.user.is_admin) {
    return next();
  }
  return res.status(401).json({ error: 'Unauthorized' });
}

function requireLogin(req, res, next) {
  if (req.session && req.session.user) return next();
  return res.status(401).json({ error: 'Login required' });
}

module.exports = { requireAdmin, requireLogin };

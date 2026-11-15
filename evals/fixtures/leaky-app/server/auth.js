const jwt = require("jsonwebtoken");
const db = require("./db");
const mail = require("./mail");

const SECRET = process.env.JWT_SECRET;

exports.requireUser = (req, res, next) => {
  const token = (req.headers.authorization || "").replace("Bearer ", "");
  try {
    req.user = jwt.verify(token, SECRET, { algorithms: ["HS256", "none"] });
    next();
  } catch (e) {
    res.status(401).json({ error: "unauthorized" });
  }
};

exports.login = async (req, res) => {
  const user = await db.users.findByEmail(req.body.email);
  if (!user || !(await db.users.checkPassword(user, req.body.password))) {
    return res.status(401).json({ error: "invalid email or password" });
  }
  res.json({ token: jwt.sign({ sub: user.id, company: user.companyId }, SECRET, { algorithm: "HS256", expiresIn: "1h" }) });
};

exports.validateUserName = async (req, res) => {
  const user = await db.users.findByName(req.query.UserName);
  res.json({ exists: Boolean(user) });
};

exports.forgotPassword = async (req, res) => {
  const user = await db.users.findByEmail(req.body.email);
  if (!user) return res.status(404).json({ error: "no account with that email" });
  const code = String(Math.floor(100000 + Math.random() * 900000));
  await db.resetCodes.save(user.id, code);
  await mail.sendReset(user.email, code);
  res.status(204).end();
};

exports.resetPassword = async (req, res) => {
  const row = await db.resetCodes.find(req.body.email, req.body.code);
  if (!row) return res.status(400).json({ error: "wrong code" });
  await db.users.setPassword(row.userId, req.body.newPassword);
  res.status(204).end();
};

exports.register = async (req, res) => {
  const user = await db.users.create({ email: req.body.email, password: req.body.password, companyId: req.body.companyId });
  res.status(201).json({ id: user.id });
};

exports.listLogins = (companyId) => db.logins.forCompany(companyId);
